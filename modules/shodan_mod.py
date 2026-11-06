"""Servicios ya expuestos según Shodan — vía InternetDB (gratis, sin key).

100% pasivo: Shodan mantiene su PROPIA base de datos pre-recolectada de internet. El endpoint
InternetDB (https://internetdb.shodan.io/<ip>) devuelve puertos abiertos, CVEs y tags YA indexados
para una IP, gratis y sin API key ni créditos. Nosotros NO escaneamos al objetivo: leemos lo que
Shodan ya sabe. (La API autenticada `host()` da más detalle pero el plan free la bloquea con 403.)
"""
import requests

INTERNETDB = "https://internetdb.shodan.io/{}"

# Puertos que, expuestos directo a internet, son hallazgos INEQUÍVOCOS de peso.
# (Se evitan a propósito 8080/8443/3000/9000: son alt-HTTP ambiguos y generan falsos positivos.)
PUERTOS_SENSIBLES = {
    1433: "Microsoft SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached",
    23: "Telnet", 3389: "RDP (escritorio remoto)", 5900: "VNC", 21: "FTP",
    2375: "Docker API (sin TLS)", 15672: "RabbitMQ", 5601: "Kibana", 8500: "Consul",
}

# Rangos de Cloudflare: sus IPs y puertos (2052/8080/8443/8880...) son de la CDN, no del origen.
# No se generan hallazgos sobre ellas para no reportar falsos positivos.
CF_PREFIJOS = ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
               "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
               "172.64.", "172.65.", "172.66.", "172.67.", "188.114.", "162.158.", "162.159.",
               "173.245.", "108.162.", "141.101.", "190.93.", "197.234.", "198.41.")


def run(ips):
    """ips: lista de direcciones IPv4 (apex + orígenes directos de subdominios sensibles)."""
    hosts = []
    hallazgos = []
    vistos = set()
    for ip in ips:
        if not ip or ip in vistos or ":" in ip:
            continue
        vistos.add(ip)
        try:
            r = requests.get(INTERNETDB.format(ip), timeout=12)
            if r.status_code == 404:
                continue  # Shodan no tiene datos de esa IP
            d = r.json()
        except Exception as e:
            hosts.append({"ip": ip, "error": str(e)[:120]})
            continue
        puertos = sorted(d.get("ports", []) or [])
        vulns = sorted(d.get("vulns", []) or [])
        hosts.append({
            "ip": ip,
            "puertos": puertos,
            "vulns": vulns,
            "tags": d.get("tags", []) or [],
            "cpes": d.get("cpes", []) or [],
            "hostnames": d.get("hostnames", []) or [],
        })
        if ip.startswith(CF_PREFIJOS):
            continue  # IP de la CDN: sus puertos/CVE no son del origen del objetivo
        sensibles = [(p, PUERTOS_SENSIBLES[p]) for p in puertos if p in PUERTOS_SENSIBLES]
        if sensibles:
            hallazgos.append({
                "ip": ip,
                "tipo": "puerto_sensible",
                "detalle": "Puerto(s) sensible(s) expuesto(s) a internet en %s: %s."
                           % (ip, ", ".join("%d (%s)" % (p, n) for p, n in sensibles)),
                "puertos": [p for p, _ in sensibles],
            })
        if vulns:
            hallazgos.append({
                "ip": ip,
                "tipo": "cve",
                "detalle": "Shodan asocia %d CVE(s) conocida(s) a %s: %s%s."
                           % (len(vulns), ip, ", ".join(vulns[:6]), " ..." if len(vulns) > 6 else ""),
                "vulns": vulns,
            })

    return {"disponible": True, "fuente": "internetdb", "hosts": hosts, "hallazgos_estructurados": hallazgos,
            "hallazgos": [h["detalle"] for h in hallazgos]}
