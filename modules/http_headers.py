"""Cabeceras de seguridad HTTP + fingerprint de tecnología.

100% pasivo: una sola petición GET a la home pública, exactamente lo que hace un navegador
al visitar el sitio. No hay fuzzing, ni rutas adivinadas, ni fuerza bruta.
"""
import re
import requests

UA = "Mozilla/5.0 (compatible; recon-pasivo/1.0; +https://github.com/lucianock/recon-pasivo)"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Fuerza HTTPS; su ausencia habilita ataques de downgrade a HTTP.",
    "Content-Security-Policy": "Mitiga XSS e inyección de contenido; ausente = mayor superficie de XSS.",
    "X-Frame-Options": "Evita clickjacking (embeber el sitio en un iframe malicioso).",
    "X-Content-Type-Options": "Evita MIME-sniffing del navegador.",
    "Referrer-Policy": "Controla qué información de origen se filtra al navegar a otros sitios.",
    "Permissions-Policy": "Restringe APIs del navegador (cámara, geoloc, etc.).",
}


def _fingerprint(headers, body):
    tech = []
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")
    if server:
        tech.append(("Server", server))
    if powered:
        tech.append(("X-Powered-By", powered))
    for h in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "Via"):
        if h in headers:
            tech.append((h, headers[h]))
    # Pistas simples en el HTML (meta generator, frameworks conocidos).
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.I)
    if m:
        tech.append(("meta generator", m.group(1)))
    for marca, patron in [("WordPress", r"/wp-content/"), ("Next.js", r"/_next/"),
                          ("React", r"react"), ("Cloudflare", r"cf-ray")]:
        if re.search(patron, (body or "") + str(headers), re.I):
            tech.append(("indicio", marca))
    return tech


def _cookies(resp):
    problemas = []
    for c in resp.cookies:
        flags = []
        if not c.secure:
            flags.append("sin Secure")
        if not c.has_nonstandard_attr("HttpOnly") and "httponly" not in str(c._rest).lower():
            flags.append("sin HttpOnly")
        if flags:
            problemas.append({"nombre": c.name, "flags": flags})
    return problemas


def run(dominio):
    url = "https://" + dominio
    try:
        resp = requests.get(url, headers={"User-Agent": UA}, timeout=12, allow_redirects=True)
    except Exception as e:
        return {"error": str(e)[:200], "url": url, "hallazgos": [
            "No se pudo conectar por HTTPS a la home (revisar disponibilidad o WAF)."]}

    headers = resp.headers
    faltantes = [(h, desc) for h, desc in SECURITY_HEADERS.items() if h not in headers]
    cookies_inseguras = _cookies(resp)
    banners = [(k, v) for k, v in headers.items()
               if k.lower() in ("server", "x-powered-by", "x-aspnet-version")
               and re.search(r"\d", v or "")]  # banners que revelan versión

    hallazgos = []
    if faltantes:
        hallazgos.append("Faltan cabeceras de seguridad: %s." % ", ".join(h for h, _ in faltantes))
    if banners:
        hallazgos.append("El servidor revela versión en banners (%s): facilita al atacante buscar exploits conocidos."
                         % "; ".join("%s: %s" % (k, v) for k, v in banners))
    if cookies_inseguras:
        hallazgos.append("Cookies sin flags de seguridad: %s."
                         % ", ".join("%s (%s)" % (c["nombre"], ", ".join(c["flags"])) for c in cookies_inseguras))

    return {
        "url_final": resp.url,
        "status": resp.status_code,
        "headers_presentes": {h: headers[h] for h in SECURITY_HEADERS if h in headers},
        "headers_faltantes": [{"header": h, "por_que": desc} for h, desc in faltantes],
        "banners_version": [{"header": k, "valor": v} for k, v in banners],
        "cookies_inseguras": cookies_inseguras,
        "fingerprint": [{"fuente": k, "valor": v} for k, v in _fingerprint(headers, resp.text[:20000])],
        "hallazgos": hallazgos,
    }
