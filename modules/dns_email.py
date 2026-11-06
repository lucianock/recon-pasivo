"""DNS y autenticación de correo — SPF, DKIM, DMARC, MX, DNSSEC.

100% pasivo: son consultas DNS públicas, lo mismo que hace cualquier cliente de mail.
"""
import dns.resolver
import dns.dnssec

# Selectores DKIM comunes para chequear presencia (no fuerza bruta: lista fija corta).
DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "s1", "mail", "dkim", "smtp"]


def _txt(name):
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=8)
        return ["".join(s.decode() if isinstance(s, bytes) else s for s in r.strings) for r in ans]
    except Exception:
        return []


def _records(name, rtype):
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=8)
        return [r.to_text() for r in ans]
    except Exception:
        return []


def check_spf(dominio):
    txts = _txt(dominio)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        return {"presente": False, "politica": None, "raw": None,
                "hallazgo": "Sin registro SPF: cualquiera puede enviar correos que aparezcan como @%s." % dominio}
    # Política del "all": -all (estricto), ~all (soft), ?all/+all (débil o abierto)
    if "-all" in spf:
        pol, hallazgo = "-all (estricto)", None
    elif "~all" in spf:
        pol, hallazgo = "~all (softfail)", "SPF en softfail (~all): no rechaza, solo marca. Recomendado endurecer a -all."
    elif "+all" in spf or "?all" in spf:
        pol, hallazgo = "+all/?all (abierto)", "SPF permisivo (+all/?all): habilita spoofing. Corregir a -all."
    else:
        pol, hallazgo = "sin mecanismo all", "SPF sin 'all' final: comportamiento indefinido en muchos receptores."
    return {"presente": True, "politica": pol, "raw": spf, "hallazgo": hallazgo}


def check_dmarc(dominio):
    txts = _txt("_dmarc." + dominio)
    dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        return {"presente": False, "politica": None, "raw": None,
                "hallazgo": "Sin registro DMARC: no hay política que instruya a los receptores qué hacer con correos falsificados."}
    low = dmarc.lower()
    if "p=reject" in low:
        pol, hallazgo = "reject", None
    elif "p=quarantine" in low:
        pol, hallazgo = "quarantine", "DMARC en quarantine: correcto pero no rechaza. Objetivo ideal: p=reject."
    elif "p=none" in low:
        pol, hallazgo = "none", "DMARC en p=none: solo monitorea, NO protege contra suplantación. Endurecer a quarantine/reject."
    else:
        pol, hallazgo = "desconocida", "DMARC presente pero sin política clara."
    return {"presente": True, "politica": pol, "raw": dmarc, "hallazgo": hallazgo}


def check_dkim(dominio):
    encontrados = []
    for sel in DKIM_SELECTORS:
        txts = _txt("%s._domainkey.%s" % (sel, dominio))
        if any("v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower() for t in txts):
            encontrados.append(sel)
    return {
        "selectores_encontrados": encontrados,
        "hallazgo": None if encontrados else
        "No se detectó DKIM en selectores comunes: los correos salientes podrían no estar firmados (revisar; puede usar un selector propio).",
    }


def check_dnssec(dominio):
    # Presencia de registros DNSKEY = DNSSEC habilitado (chequeo de presencia, no validación completa).
    dnskey = _records(dominio, "DNSKEY")
    return {"habilitado": bool(dnskey),
            "hallazgo": None if dnskey else
            "DNSSEC no habilitado: el dominio es más susceptible a envenenamiento de caché DNS (riesgo bajo/medio)."}


def run(dominio):
    spf = check_spf(dominio)
    dmarc = check_dmarc(dominio)
    dkim = check_dkim(dominio)
    dnssec = check_dnssec(dominio)
    return {
        "a": _records(dominio, "A"),
        "aaaa": _records(dominio, "AAAA"),
        "mx": _records(dominio, "MX"),
        "ns": _records(dominio, "NS"),
        "caa": _records(dominio, "CAA"),
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "dnssec": dnssec,
        "hallazgos": [h for h in (spf["hallazgo"], dmarc["hallazgo"], dkim["hallazgo"], dnssec["hallazgo"]) if h],
    }
