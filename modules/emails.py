"""Correos recolectables públicamente.

100% pasivo: extrae direcciones que aparecen en las propias páginas públicas del sitio.
NO afirma que estén en brechas (el chequeo de brechas por dominio en HIBP exige probar que sos
dueño del dominio). El valor es mostrar la superficie: "estos correos se recolectan sin esfuerzo
y son blanco directo de phishing dirigido a tu organización de salud".
"""
import re
import requests

UA = "Mozilla/5.0 (compatible; recon-pasivo/1.0; +https://github.com/lucianock/recon-pasivo)"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Páginas comunes donde suelen figurar correos.
RUTAS = ["", "/contacto", "/contact", "/nosotros", "/about", "/equipo", "/team", "/soporte"]


def run(dominio):
    encontrados = set()
    fuentes = {}
    for ruta in RUTAS:
        url = "https://" + dominio + ruta
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=10, allow_redirects=True)
            if r.status_code >= 400:
                continue
            for m in EMAIL_RE.findall(r.text):
                m = m.lower()
                # Filtrar imágenes/assets que matchean el patrón por casualidad
                if m.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
                    continue
                encontrados.add(m)
                fuentes.setdefault(m, ruta or "/")
        except Exception:
            continue

    propios = sorted(e for e in encontrados if e.endswith("@" + dominio))
    otros = sorted(e for e in encontrados if not e.endswith("@" + dominio))
    hallazgos = []
    if propios:
        hallazgos.append(
            "%d correo(s) corporativo(s) recolectable(s) directamente del sitio (%s): blanco de phishing dirigido."
            % (len(propios), ", ".join(propios[:6]) + (" ..." if len(propios) > 6 else "")))
    return {"corporativos": propios, "otros": otros, "fuentes": fuentes, "hallazgos": hallazgos}
