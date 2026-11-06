#!/usr/bin/env python3
"""Genera el informe de exposición externa a partir del JSON de passive_recon.

Uso:
    python report.py out/example-com.json
    -> out/informe-example-com.html

Convierte los datos crudos en hallazgos con severidad e impacto de negocio (tabla de reglas),
calcula un semáforo global y renderiza una plantilla HTML. El HTML es autocontenido:
se puede abrir en el navegador e imprimir a PDF, o publicar en una URL.
"""
import os
import sys
import json
import datetime
from jinja2 import Environment, FileSystemLoader

BASE = os.path.dirname(os.path.abspath(__file__))

SEV_ORDEN = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1, "Informativa": 0}


def _cpe_legible(cpe):
    """cpe:/a:mariadb:mariadb:10.6.27-MariaDB -> 'mariadb 10.6.27-MariaDB'"""
    partes = cpe.replace("cpe:/a:", "").replace("cpe:/o:", "").split(":")
    prod = partes[1] if len(partes) > 1 else partes[0]
    ver = partes[2] if len(partes) > 2 else None
    return "%s %s" % (prod, ver) if ver else prod


def _servicios_desde_cpes(cpes):
    vistos, out = set(), []
    for cpe in cpes or []:
        legible = _cpe_legible(cpe)
        prod = legible.split(" ")[0]
        if prod in vistos:
            continue
        vistos.add(prod)
        out.append(legible)
    return out


def _otros_dominios_en_ip(hostnames, dominio):
    """Hostnames en la misma IP que NO son del dominio evaluado -> evidencia de hosting compartido.

    Usa el primer label del dominio (ej. 'silab' de silab.com.ar) en vez de split[-2], que con TLDs
    compuestos (.com.ar, .co.uk) daría 'com' y filtraría de más (casi todo hostname contiene '.com.').
    """
    base = dominio.split(".")[0] if "." in dominio else dominio
    return sorted({h for h in (hostnames or []) if base not in h.lower()})


def hallazgos_desde_json(d):
    """Traduce los datos crudos a hallazgos curados {titulo, severidad, impacto, evidencia, recomendacion}."""
    H = []
    dominio = d["dominio"]
    dns = d.get("dns_email", {})
    http = d.get("http", {})
    subs = d.get("subdominios", {})
    cat = subs.get("categorias", {})
    emails = d.get("emails", {})
    shodan = d.get("shodan", {})
    vt = d.get("virustotal", {})

    # --- Subdominios: entornos no productivos ---
    if cat.get("entornos_no_productivos"):
        lst = cat["entornos_no_productivos"]
        H.append({
            "titulo": "Entornos de desarrollo y prueba enumerables públicamente",
            "severidad": "Media",
            "categoria": "Superficie de ataque",
            "impacto": ("Los registros públicos de Certificate Transparency exponen %d entornos no productivos "
                        "(dev/test/staging). Estos entornos suelen tener controles más laxos que producción, "
                        "credenciales por defecto o datos reales copiados — y son el punto de entrada preferido "
                        "de un atacante que hace reconocimiento sin tocar nada." % len(lst)),
            "evidencia": lst[:14],
            "recomendacion": ("Restringir el acceso a estos entornos por IP/VPN o autenticación previa, y evitar "
                              "que emitan certificados públicos con nombres descriptivos. Confirmar que ninguno "
                              "exponga datos de producción."),
        })

    # --- Subdominios: herramientas internas ---
    if cat.get("herramientas_internas"):
        lst = cat["herramientas_internas"]
        H.append({
            "titulo": "Herramientas internas identificables por nombre",
            "severidad": "Media",
            "categoria": "Superficie de ataque",
            "impacto": ("Se identifican por nombre instancias de herramientas internas (%s). Un atacante sabe "
                        "exactamente qué software buscar vulnerabilidades sobre, y muchos de estos paneles "
                        "(GitLab, Grafana, backups) no deberían ser accesibles desde internet abierto."
                        % ", ".join(lst[:8])),
            "evidencia": lst,
            "recomendacion": ("Verificar que cada herramienta esté detrás de VPN/SSO y no expuesta públicamente; "
                              "mantenerlas actualizadas y con MFA."),
        })

    # --- Subdominios: datos de salud (FHIR) ---
    if cat.get("datos_salud"):
        lst = cat["datos_salud"]
        H.append({
            "titulo": "Endpoints de datos clínicos (FHIR) visibles en registros públicos",
            "severidad": "Media",
            "categoria": "Datos sensibles",
            "impacto": ("Existen subdominios asociados al estándar FHIR/HL7 de intercambio de datos clínicos (%s). "
                        "Para una empresa de salud, la infraestructura que maneja historias clínicas es el activo de "
                        "mayor criticidad regulatoria y reputacional. Su sola visibilidad orienta a un atacante hacia "
                        "el objetivo de mayor valor." % ", ".join(lst)),
            "evidencia": lst,
            "recomendacion": ("Priorizar la verificación de autenticación robusta, cifrado y control de acceso en estos "
                              "endpoints; considerar no exponer nombres tan descriptivos en certificados públicos."),
        })

    # --- Cabeceras HTTP ---
    faltantes = [x["header"] for x in http.get("headers_faltantes", [])]
    if faltantes:
        H.append({
            "titulo": "Faltan cabeceras de seguridad HTTP",
            "severidad": "Media",
            "categoria": "Configuración web",
            "impacto": ("El sitio principal no envía %s. Su ausencia habilita ataques de downgrade a HTTP (sin HSTS), "
                        "clickjacking (sin X-Frame-Options) y aumenta la superficie de XSS." % ", ".join(faltantes)),
            "evidencia": faltantes,
            "recomendacion": ("Agregar HSTS, X-Frame-Options (o CSP frame-ancestors), X-Content-Type-Options, "
                              "Referrer-Policy y Permissions-Policy. Es un cambio de configuración de bajo riesgo."),
        })

    # --- Fingerprint / divulgación de versión ---
    fp = {x["fuente"]: x["valor"] for x in http.get("fingerprint", [])}
    if fp.get("X-Powered-By"):
        H.append({
            "titulo": "El servidor revela su stack tecnológico",
            "severidad": "Baja",
            "categoria": "Divulgación de información",
            "impacto": ("La cabecera X-Powered-By expone '%s'. Revelar el framework facilita al atacante buscar "
                        "exploits específicos de esa tecnología y versión." % fp["X-Powered-By"]),
            "evidencia": ["X-Powered-By: " + fp["X-Powered-By"]],
            "recomendacion": "Desactivar la cabecera X-Powered-By en el servidor de aplicación.",
        })

    # --- SPF ---
    spf = dns.get("spf", {})
    if spf.get("hallazgo"):
        H.append({
            "titulo": "Política SPF en softfail",
            "severidad": "Baja",
            "categoria": "Correo",
            "impacto": ("El SPF usa ~all (softfail): no rechaza correos falsificados, solo los marca. "
                        "El riesgo está mitigado por el DMARC en 'reject', pero endurecer el SPF cierra el hueco por completo."),
            "evidencia": [spf.get("raw", "")],
            "recomendacion": "Cambiar ~all por -all una vez confirmados todos los remitentes legítimos.",
        })

    # --- DMARC ---
    dmarc = dns.get("dmarc", {})
    if dmarc.get("hallazgo"):
        ausente = not dmarc.get("presente")
        if ausente and emails.get("corporativos"):
            severidad = "Alta"
        elif ausente or dmarc.get("politica") == "none":
            severidad = "Media"
        else:
            severidad = "Baja"
        H.append({
            "titulo": "Dominio sin protección fuerte contra suplantación de correo" if ausente else "Política DMARC débil",
            "severidad": severidad,
            "categoria": "Correo",
            "impacto": (("Sin DMARC, cualquiera puede enviar correos falsificados en nombre de %s y llegan igual a "
                         "destino — el vector clásico de phishing dirigido a clientes o proveedores." % dominio)
                        if ausente else
                        ("DMARC está presente pero no rechaza correos falsificados: %s" % dmarc.get("hallazgo"))),
            "evidencia": [dmarc.get("raw") or ("Sin registro _dmarc.%s" % dominio)],
            "recomendacion": ("Publicar un registro DMARC en p=quarantine y migrar a p=reject una vez confirmados "
                               "los remitentes legítimos." if ausente else
                               "Endurecer la política DMARC a p=reject una vez confirmados los remitentes legítimos."),
        })

    # --- DNSSEC ---
    if not dns.get("dnssec", {}).get("habilitado", True):
        H.append({
            "titulo": "DNSSEC no habilitado",
            "severidad": "Baja",
            "categoria": "DNS",
            "impacto": "Sin DNSSEC, el dominio es más susceptible a envenenamiento de caché DNS (riesgo bajo).",
            "evidencia": ["No se detectaron registros DNSKEY"],
            "recomendacion": "Habilitar DNSSEC (con Cloudflare es un cambio de un clic).",
        })

    # --- Emails recolectables ---
    if emails.get("corporativos"):
        H.append({
            "titulo": "Correos corporativos recolectables públicamente",
            "severidad": "Informativa",
            "categoria": "Ingeniería social",
            "impacto": ("Se recolectan sin esfuerzo correos corporativos (%s). Son el blanco directo de campañas de "
                        "phishing dirigido a la organización." % ", ".join(emails["corporativos"][:6])),
            "evidencia": emails["corporativos"],
            "recomendacion": "Concientización antiphishing al personal; considerar formularios en vez de correos en texto plano.",
        })

    # --- VirusTotal (reputación pre-calculada por ~90 motores) ---
    if vt.get("disponible") and vt.get("encontrado") and (vt.get("maliciosos") or vt.get("sospechosos")):
        H.append({
            "titulo": "El dominio está marcado en bases de reputación de seguridad",
            "severidad": "Alta" if vt.get("maliciosos") else "Media",
            "categoria": "Reputación",
            "impacto": (("%d de %d motores de seguridad marcan %s como MALICIOSO en VirusTotal. Puede deberse a una "
                         "brecha previa, un subdominio comprometido, o contenido abusivo alojado ahí sin que la "
                         "organización lo sepa — conviene confirmarlo cuanto antes." % (vt["maliciosos"], vt["total_motores"], dominio))
                        if vt.get("maliciosos") else
                        ("%d de %d motores marcan %s como sospechoso en VirusTotal — vale la pena revisar por qué."
                         % (vt["sospechosos"], vt["total_motores"], dominio))),
            "evidencia": (["MOTORES: %s" % m for m in vt.get("motores_marcaron", [])[:5]]
                          or ["Ver reporte completo en virustotal.com/gui/domain/%s" % dominio]),
            "recomendacion": ("Revisar el reporte completo en VirusTotal, confirmar si es un falso positivo o una "
                               "amenaza real, y si corresponde solicitar la remoción del listado una vez resuelto."),
        })

    # --- Shodan / InternetDB (datos pre-recolectados) ---
    ip_a_host = {h["ip"]: h.get("apunta_a", []) for h in shodan.get("hosts", [])}
    ip_a_hostdata = {h["ip"]: h for h in shodan.get("hosts", [])}
    for h in shodan.get("hallazgos_estructurados", []):
        apunta = ip_a_host.get(h["ip"], [])
        ctx = (" (%s)" % ", ".join(apunta[:3])) if apunta else ""
        if h["tipo"] == "puerto_sensible":
            es_db = any(p in (1433, 3306, 5432, 6379, 27017, 9200, 5984) for p in h.get("puertos", []))
            hostdata = ip_a_hostdata.get(h["ip"], {})
            evidencia = [
                "IP: %s%s" % (h["ip"], ctx),
                "PUERTOS ABIERTOS: %s" % ", ".join(map(str, hostdata.get("puertos", h.get("puertos", [])))),
            ]
            servicios = _servicios_desde_cpes(hostdata.get("cpes"))
            if servicios:
                evidencia.append("SERVICIOS DETECTADOS: %s" % ", ".join(servicios))
            otros = _otros_dominios_en_ip(hostdata.get("hostnames"), dominio)
            impacto_extra = (" Una base de datos accesible desde internet es uno de los vectores de compromiso más directos."
                              if es_db else " Estos servicios no deberían ser accesibles públicamente.")
            if otros:
                evidencia.append("ESTE SERVIDOR TAMBIÉN ALOJA: %s (hosting compartido)" % ", ".join(otros[:3]))
                impacto_extra += (" Además, el servidor es de hosting compartido: una brecha en cualquiera de los "
                                   "otros sitios alojados ahí puede afectar también a %s." % dominio)
            H.append({
                "titulo": "Servicio sensible expuesto directamente a internet",
                "severidad": "Alta" if es_db else "Media",
                "categoria": "Superficie de ataque",
                "impacto": h["detalle"].replace(h["ip"], h["ip"] + ctx) + impacto_extra,
                "evidencia": evidencia,
                "recomendacion": ("Cerrar el puerto al público (firewall/security group) y permitir el acceso solo "
                                  "desde IPs autorizadas o VPN. Confirmar que no haya autenticación por defecto."),
            })
        elif h["tipo"] == "cve":
            H.append({
                "titulo": "Vulnerabilidades conocidas (CVE) en un servicio expuesto",
                "severidad": "Media",
                "categoria": "Vulnerabilidades",
                "impacto": h["detalle"].replace(h["ip"], h["ip"] + ctx) +
                " Son CVEs que Shodan ya asoció al servicio; conviene confirmar versión y parchear.",
                "evidencia": ["%s%s" % (h["ip"], ctx)] + h.get("vulns", [])[:8],
                "recomendacion": "Verificar la versión real del servicio y aplicar los parches correspondientes.",
            })

    H.sort(key=lambda x: SEV_ORDEN.get(x["severidad"], 0), reverse=True)
    for i, h in enumerate(H, 1):
        h["id"] = "F-%02d" % i
    return H


def cosas_bien(d):
    """Lo que el objetivo hace BIEN — el informe debe ser honesto para ser creíble."""
    bien = []
    dns = d.get("dns_email", {})
    if dns.get("dmarc", {}).get("politica") == "reject":
        bien.append("DMARC configurado en 'reject': protección fuerte contra suplantación de correo.")
    if dns.get("dkim", {}).get("selectores_encontrados"):
        bien.append("Correo saliente firmado con DKIM.")
    tls = d.get("tls", {}).get("certificado", {})
    if (tls.get("protocolo_negociado") or "").startswith("TLSv1.3"):
        bien.append("TLS 1.3 vigente con certificado válido.")
    fp = {x["fuente"]: x["valor"] for x in d.get("http", {}).get("fingerprint", [])}
    if "cloudflare" in str(fp).lower():
        bien.append("Sitio detrás de Cloudflare (CDN/WAF), lo que mitiga varios ataques automatizados.")
    if d.get("http", {}).get("headers_presentes"):
        bien.append("Ya envía Content-Security-Policy (base sobre la que mejorar).")
    vt = d.get("virustotal", {})
    if vt.get("limpio"):
        bien.append("Reputación limpia en VirusTotal: 0 de %d motores de seguridad lo marcan como "
                     "malicioso o sospechoso." % vt.get("total_motores", 0))
    return bien


def semaforo(hallazgos):
    if any(h["severidad"] in ("Crítica", "Alta") for h in hallazgos):
        return ("alta", "Riesgo alto — atención requerida", "#e35d6a")
    if any(h["severidad"] == "Media" for h in hallazgos):
        return ("media", "Riesgo medio — mejoras recomendadas", "#d1a054")
    return ("baja", "Riesgo bajo — postura sólida", "#5fb488")


def generar(d):
    """A partir del dict de passive_recon, arma hallazgos + HTML. No escribe archivos.

    Devuelve (html, ctx) donde ctx trae hallazgos/bien/semáforo/conteo para reusar
    (ej. armar el borrador de mail) sin tener que re-parsear el HTML.
    """
    hallazgos = hallazgos_desde_json(d)
    bien = cosas_bien(d)
    sem_icono, sem_texto, sem_color = semaforo(hallazgos)

    conteo = {}
    for h in hallazgos:
        conteo[h["severidad"]] = conteo.get(h["severidad"], 0) + 1

    dorks = (d.get("dorks", {}) or {}).get("consultas", [])[:3]

    env = Environment(loader=FileSystemLoader(os.path.join(BASE, "templates")), autoescape=True)
    tpl = env.get_template("informe.html")
    html = tpl.render(
        dominio=d["dominio"],
        fecha=datetime.date.fromisoformat(d["fecha"]).strftime("%d/%m/%Y"),
        alcance=d["alcance"],
        hallazgos=hallazgos,
        bien=bien,
        sem_icono=sem_icono, sem_texto=sem_texto, sem_color=sem_color,
        conteo=conteo,
        total_subdominios=d.get("subdominios", {}).get("total", 0),
        dorks=dorks,
    )
    ctx = {"hallazgos": hallazgos, "bien": bien, "sem_icono": sem_icono, "sem_texto": sem_texto,
           "conteo": conteo, "dominio": d["dominio"]}
    return html, ctx


def main():
    if len(sys.argv) < 2:
        print("Uso: python report.py out/<slug>.json")
        sys.exit(1)
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    html, ctx = generar(d)
    out = os.path.join(BASE, "out", "informe-" + d["dominio"].replace(".", "-") + ".html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print("[OK] Informe: %s" % out)
    print("     %d hallazgos (%s) · %d cosas bien · semáforo %s"
          % (len(ctx["hallazgos"]), ", ".join("%s: %d" % (k, v) for k, v in ctx["conteo"].items()),
             len(ctx["bien"]), ctx["sem_icono"]))


if __name__ == "__main__":
    main()
