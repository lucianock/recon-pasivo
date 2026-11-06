"""Subdominios vía Certificate Transparency (crt.sh).

100% pasivo: los logs de Certificate Transparency son un registro PÚBLICO de todos los
certificados TLS emitidos. Consultarlos NO toca la infraestructura del objetivo — es leer
una base de datos pública. No se resuelven ni se escanean los subdominios encontrados.
"""
import re
import requests

# Tokens que, por su nombre, indican entornos/herramientas que no deberían estar tan expuestos.
# Se buscan como tokens sueltos separando el subdominio por "." y "-".
ENTORNOS = {"dev", "test", "staging", "stg", "qa", "uat", "sandbox", "beta", "demo", "pre", "preprod"}
HERRAMIENTAS = {"gitlab", "git", "jenkins", "grafana", "kibana", "bookstack", "jira", "confluence",
                "phpmyadmin", "adminer", "portainer", "vault", "consul", "nexus", "sonar",
                "backup", "cubebackup", "vpn", "ftp", "sftp"}
ACCESO = {"admin", "adminer", "backoffice", "auth", "login", "panel", "dashboard", "sso", "cas"}
DATOS_SALUD = {"fhir", "hl7", "hce", "historia"}

UA = "Mozilla/5.0 (compatible; recon-pasivo/1.0; +https://github.com/lucianock/recon-pasivo)"


def _tokens(sub, dominio):
    prefijo = sub[: -len(dominio) - 1]  # saca ".dominio.tld"
    return set(re.split(r"[.\-]", prefijo))


def _clasificar(subdominios, dominio):
    cat = {"entornos_no_productivos": [], "herramientas_internas": [], "portales_acceso": [], "datos_salud": []}
    for s in subdominios:
        t = _tokens(s, dominio)
        if t & ENTORNOS:
            cat["entornos_no_productivos"].append(s)
        if t & HERRAMIENTAS:
            cat["herramientas_internas"].append(s)
        if t & ACCESO:
            cat["portales_acceso"].append(s)
        if t & DATOS_SALUD:
            cat["datos_salud"].append(s)
    return {k: sorted(set(v)) for k, v in cat.items()}


def _certspotter(dominio):
    """Certificate Transparency vía certspotter (más estable que crt.sh)."""
    url = ("https://api.certspotter.com/v1/issuances?domain={}"
           "&include_subdomains=true&expand=dns_names".format(dominio))
    r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
    nombres = set()
    for e in r.json():
        for n in e.get("dns_names", []):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(dominio) and n != dominio:
                nombres.add(n)
    return nombres


def _crtsh(dominio):
    """Fallback: crt.sh (a veces rate-limitea o devuelve vacío)."""
    r = requests.get("https://crt.sh/?q=%25.{}&output=json".format(dominio),
                     headers={"User-Agent": UA}, timeout=30)
    nombres = set()
    for e in r.json():
        for campo in ("name_value", "common_name"):
            for n in (e.get(campo) or "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(dominio) and n != dominio:
                    nombres.add(n)
    return nombres


def run(dominio):
    nombres = set()
    fuente = None
    for nombre_fuente, fn in (("certspotter", _certspotter), ("crt.sh", _crtsh)):
        try:
            nombres = fn(dominio)
            if nombres:
                fuente = nombre_fuente
                break
        except Exception:
            continue
    if not nombres:
        return {"error": "no se pudo consultar CT (certspotter/crt.sh)", "subdominios": [],
                "sensibles": [], "hallazgos": []}

    subdominios = sorted(nombres)
    cat = _clasificar(subdominios, dominio)

    hallazgos = []
    if len(subdominios) > 25:
        hallazgos.append("Superficie amplia: %d subdominios visibles en registros públicos de certificados (Certificate Transparency)." % len(subdominios))
    if cat["entornos_no_productivos"]:
        hallazgos.append("Entornos no productivos (dev/test/staging) enumerables públicamente: %s%s. Suelen tener controles más laxos y datos reales."
                         % (", ".join(cat["entornos_no_productivos"][:8]), " ..." if len(cat["entornos_no_productivos"]) > 8 else ""))
    if cat["herramientas_internas"]:
        hallazgos.append("Herramientas internas identificables por nombre: %s. Conviene verificar que no sean accesibles desde internet."
                         % ", ".join(cat["herramientas_internas"][:10]))
    if cat["datos_salud"]:
        hallazgos.append("Endpoints asociados a datos clínicos (FHIR/HL7) visibles en el registro público: %s. Superficie de máxima criticidad para una empresa de salud."
                         % ", ".join(cat["datos_salud"]))

    return {"fuente": fuente, "total": len(subdominios), "subdominios": subdominios,
            "categorias": cat, "hallazgos": hallazgos}
