"""Estado TLS/SSL del dominio.

Estrategia pasiva: leer el certificado que el servidor ya presenta públicamente a cualquier
cliente (un handshake TLS estándar, lo mismo que hace un navegador). Opcionalmente enriquece
con la API pública de SSL Labs (ellos escanean, nosotros solo leemos el resultado).
"""
import ssl
import socket
import datetime
import requests

SSLLABS_API = "https://api.ssllabs.com/api/v3/analyze"


def _leer_certificado(dominio, puerto=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((dominio, puerto), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
        # Vencimiento
        not_after = cert.get("notAfter")
        vence = None
        dias_restantes = None
        if not_after:
            vence_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            vence = vence_dt.date().isoformat()
            dias_restantes = (vence_dt - datetime.datetime.utcnow()).days
        emisor = dict(x[0] for x in cert.get("issuer", []))
        return {
            "protocolo_negociado": version,
            "emisor": emisor.get("organizationName") or emisor.get("commonName"),
            "vence": vence,
            "dias_restantes": dias_restantes,
            "sujeto_alt": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
        }
    except Exception as e:
        return {"error": str(e)[:200]}


def _ssllabs(dominio, esperar=False):
    """Consulta la API pública de SSL Labs. Devuelve grade si ya está cacheado; no bloquea si esperar=False."""
    try:
        params = {"host": dominio, "fromCache": "on", "all": "done"}
        if not esperar:
            params["startNew"] = "off"
        r = requests.get(SSLLABS_API, params=params, timeout=15)
        data = r.json()
        if data.get("status") == "READY":
            grades = [ep.get("grade") for ep in data.get("endpoints", []) if ep.get("grade")]
            return {"status": "READY", "grades": grades}
        return {"status": data.get("status")}
    except Exception as e:
        return {"error": str(e)[:150]}


def run(dominio):
    cert = _leer_certificado(dominio)
    ssllabs = _ssllabs(dominio)
    hallazgos = []
    if cert.get("error"):
        hallazgos.append("No se pudo completar el handshake TLS (revisar).")
    else:
        proto = (cert.get("protocolo_negociado") or "")
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            hallazgos.append("El servidor negoció %s (protocolo obsoleto): debería exigir TLS 1.2+." % proto)
        dias = cert.get("dias_restantes")
        if dias is not None and dias < 21:
            hallazgos.append("El certificado TLS vence en %d días: riesgo de caída del sitio si no se renueva." % dias)
    grades = ssllabs.get("grades") or []
    malas = [g for g in grades if g and g[0] in ("C", "D", "E", "F", "T")]
    if malas:
        hallazgos.append("SSL Labs califica el TLS como %s (por debajo de A): configuración mejorable." % ", ".join(malas))
    return {"certificado": cert, "ssllabs": ssllabs, "hallazgos": hallazgos}
