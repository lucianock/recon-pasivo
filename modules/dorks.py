"""Google dorks — genera las consultas para revisar lo YA indexado por buscadores.

100% pasivo: un dork es solo una búsqueda en Google. Leer resultados que el buscador ya indexó
es lo mismo que cualquier persona puede hacer. Este módulo NO scrapea Google (va contra sus ToS
y se bloquea): genera la lista de consultas + URLs para revisar a mano o con la herramienta de
búsqueda del operador. Los hallazgos reales se cargan tras la revisión manual.
"""
import urllib.parse

# Dorks de mayor señal para exposición: archivos sensibles, paneles, listados de directorio.
PLANTILLAS = [
    ('site:{d} ext:sql | ext:env | ext:log | ext:bak | ext:old', "Archivos sensibles (backups, .env, dumps SQL) indexados"),
    ('site:{d} ext:pdf | ext:xls | ext:xlsx | ext:doc | ext:docx', "Documentos que pueden contener datos internos o metadatos"),
    ('site:{d} intitle:"index of"', "Listados de directorio abiertos"),
    ('site:{d} inurl:admin | inurl:login | inurl:panel | inurl:dashboard', "Paneles de administración/login indexados"),
    ('site:{d} inurl:api | inurl:swagger | inurl:graphql', "Documentación de APIs expuesta"),
    ('site:{d} intext:"password" | intext:"api_key" | intext:"secret"', "Posibles credenciales en páginas indexadas"),
    ('site:{d} inurl:.git | inurl:.svn | inurl:wp-config', "Archivos de configuración/control de versiones"),
    ('site:*.{d}', "Subdominios indexados por Google"),
]


def run(dominio):
    consultas = []
    for tpl, desc in PLANTILLAS:
        q = tpl.format(d=dominio)
        consultas.append({
            "descripcion": desc,
            "query": q,
            "url": "https://www.google.com/search?q=" + urllib.parse.quote(q),
        })
    return {
        "consultas": consultas,
        "nota": "Revisar manualmente (o con la herramienta de búsqueda). Cargar en 'hallazgos_manuales' del JSON lo que aparezca.",
        "hallazgos_manuales": [],
        "hallazgos": [],
    }
