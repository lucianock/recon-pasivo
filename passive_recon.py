#!/usr/bin/env python3
"""Recon pasiva de exposición externa.

Uso:
    python passive_recon.py <dominio>
    python passive_recon.py example.com

Produce out/<slug>.json con toda la evidencia. TODO lo que corre es estrictamente pasivo:
consultas a datos públicos (DNS, Certificate Transparency, home del sitio) o a bases
pre-recolectadas por terceros (Shodan). No hay escaneo activo, ni fuerza bruta, ni acceso a la
infraestructura del objetivo. Ver "Uso responsable" en el README.
"""
import os
import re
import sys
import json
import socket
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules import dns_email, http_headers, tls, subdomains_ct, shodan_mod, emails, dorks, virustotal

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")


def cargar_env():
    """Carga .env local (si existe) sin dependencias externas."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def slug(dominio):
    return re.sub(r"[^a-z0-9]+", "-", dominio.lower()).strip("-")


# Rangos comunes de Cloudflare: si el subdominio está detrás de la CDN, la IP no es del origen
# y un lookup de Shodan solo mostraría Cloudflare. Se filtran para quedarnos con orígenes reales.
CF_PREFIJOS = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
               "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
               "172.64.", "172.65.", "172.66.", "172.67.", "188.114.", "162.158.", "162.159.",
               "173.245.", "108.162.", "141.101.", "190.93.", "197.234.", "198.41.")


def _es_cloudflare(ip):
    return ip.startswith(CF_PREFIJOS)


def _resolver(host):
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
                       if ":" not in r[4][0]})  # solo IPv4 para Shodan
    except Exception:
        return []


def resolver_ips(dominio, dns_data, subs_data):
    """IPs para Shodan: apex + subdominios sensibles que resuelvan a un origen directo (no Cloudflare)."""
    ips = {}
    for ip in _resolver(dominio):
        ips.setdefault(ip, []).append(dominio)
    # Resolver los subdominios de las categorías sensibles y quedarnos con orígenes directos.
    cat = subs_data.get("categorias", {})
    sensibles = sorted(set(sum((cat.get(k, []) for k in
                    ("herramientas_internas", "datos_salud", "entornos_no_productivos", "portales_acceso")), [])))
    for sub in sensibles[:40]:  # tope prudente
        for ip in _resolver(sub):
            if not _es_cloudflare(ip):
                ips.setdefault(ip, []).append(sub)
    return ips


def recon(dominio, verbose=True, cargar_dotenv=True):
    """Corre toda la recon pasiva sobre un dominio y devuelve el dict de resultado.

    Reusable desde passive_recon.py (CLI) y desde scan.py (orquestador de un comando).
    """
    dominio = dominio.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    if cargar_dotenv:
        cargar_env()

    def log(msg):
        if verbose:
            print(msg)

    log("[*] Recon pasiva de %s (solo fuentes públicas)" % dominio)
    resultado = {
        "dominio": dominio,
        "fecha": datetime.date.today().isoformat(),
        "corrida_timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "alcance": "Análisis no intrusivo basado únicamente en información pública. Sin acceso a sistemas ni escaneo activo.",
        # Evidencia de que la recon fue 100% pasiva, por si hace falta responder un reclamo (ver guias/10):
        # las respuestas crudas de cada fuente quedan igual en las secciones de abajo (dns_email.raw, tls.raw, etc.)
        "fuentes_consultadas": [
            "Resolución DNS pública (SPF/DKIM/DMARC/DNSSEC vía resolvers estándar)",
            "Handshake TLS como cliente normal + API pública SSL Labs",
            "Un GET HTTP a la home, igual que cualquier visitante o buscador",
            "Certificate Transparency logs públicos (certspotter/crt.sh) para subdominios",
            "Base pública InternetDB de Shodan (datos ya recolectados por terceros, sin conexión propia al objetivo)",
            "Contenido ya publicado en el propio sitio (correos, texto)",
        ],
    }

    log("  - DNS / autenticación de correo (SPF, DKIM, DMARC, DNSSEC)")
    resultado["dns_email"] = dns_email.run(dominio)

    log("  - Cabeceras HTTP y fingerprint")
    resultado["http"] = http_headers.run(dominio)

    log("  - TLS / certificado")
    resultado["tls"] = tls.run(dominio)

    log("  - Subdominios (Certificate Transparency)")
    resultado["subdominios"] = subdomains_ct.run(dominio)

    log("  - Correos recolectables")
    resultado["emails"] = emails.run(dominio)

    log("  - Google dorks (consultas para revisión)")
    resultado["dorks"] = dorks.run(dominio)

    log("  - Reputación de dominio (VirusTotal)")
    resultado["virustotal"] = virustotal.run(dominio)

    ip_map = resolver_ips(dominio, resultado["dns_email"], resultado["subdominios"])
    ips = list(ip_map.keys())
    log("  - Shodan (datos pre-recolectados) para %d IP(s) [apex + orígenes directos de subdominios]" % len(ips))
    resultado["shodan"] = shodan_mod.run(ips)
    for host in resultado["shodan"].get("hosts", []):
        host["apunta_a"] = ip_map.get(host["ip"], [])
    resultado["ips"] = ip_map

    resultado["hallazgos_auto"] = []
    for seccion in ("dns_email", "http", "tls", "subdominios", "emails", "shodan", "virustotal"):
        for h in resultado.get(seccion, {}).get("hallazgos", []):
            resultado["hallazgos_auto"].append({"seccion": seccion, "texto": h})

    return resultado


def guardar(resultado):
    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = os.path.join(OUT_DIR, slug(resultado["dominio"]) + ".json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, ensure_ascii=False, indent=2)
    return out_path


def main():
    if len(sys.argv) < 2:
        print("Uso: python passive_recon.py <dominio>")
        sys.exit(1)
    resultado = recon(sys.argv[1])
    out_path = guardar(resultado)
    print("\n[OK] %d hallazgo(s) automático(s). Guardado en %s" % (len(resultado["hallazgos_auto"]), out_path))
    print("     Siguiente: revisar a mano + 'python report.py %s'" % out_path)


if __name__ == "__main__":
    main()
