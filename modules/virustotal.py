"""Reputación de dominio según VirusTotal — motores antivirus/antiphishing (~90) + puntaje de la comunidad.

100% pasivo: VirusTotal mantiene su PROPIA base de reputación pre-calculada a partir de escaneos que
ellos ya corrieron y de reportes de la comunidad. Nosotros NO escaneamos al objetivo: consultamos el
reporte que VirusTotal ya tiene. Requiere VT_API_KEY (gratis, https://www.virustotal.com/gui/join-us,
plan "Public API": 4 req/min y 500 req/día — de sobra para uso normal). Si no hay key
configurada, el módulo degrada limpio (disponible=False) y el resto del informe sigue funcionando.
"""
import os
import requests

API = "https://www.virustotal.com/api/v3/domains/{}"


def run(dominio):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"disponible": False, "motivo": "sin VT_API_KEY en .env", "hallazgos": []}

    try:
        r = requests.get(API.format(dominio), headers={"x-apikey": key}, timeout=12)
        if r.status_code == 404:
            return {"disponible": True, "encontrado": False, "hallazgos": []}
        if r.status_code == 401:
            return {"disponible": False, "motivo": "VT_API_KEY inválida (401)", "hallazgos": []}
        if r.status_code == 429:
            return {"disponible": False, "motivo": "límite de cuota de VirusTotal alcanzado (429)", "hallazgos": []}
        r.raise_for_status()
        d = r.json().get("data", {}).get("attributes", {})
    except Exception as e:
        return {"disponible": False, "motivo": str(e)[:150], "hallazgos": []}

    stats = d.get("last_analysis_stats", {}) or {}
    maliciosos = stats.get("malicious", 0)
    sospechosos = stats.get("suspicious", 0)
    total_motores = sum(stats.values()) or 0
    reputacion = d.get("reputation", 0)
    votos = d.get("total_votes", {}) or {}
    categorias = sorted(set((d.get("categories") or {}).values()))

    motores_marcaron = []
    if maliciosos or sospechosos:
        for motor, veredicto in (d.get("last_analysis_results") or {}).items():
            cat = veredicto.get("category")
            if cat in ("malicious", "suspicious"):
                motores_marcaron.append("%s: %s" % (motor, veredicto.get("result") or cat))

    hallazgos = []
    if maliciosos > 0:
        hallazgos.append(
            "%d de %d motores de seguridad marcan el dominio como MALICIOSO en VirusTotal — "
            "puede tratarse de una comprometida previa, un subdominio abusado, o un falso positivo "
            "a confirmar." % (maliciosos, total_motores)
        )
    elif sospechosos > 0:
        hallazgos.append(
            "%d de %d motores marcan el dominio como sospechoso en VirusTotal — vale la pena revisar por qué."
            % (sospechosos, total_motores)
        )
    if reputacion < 0:
        hallazgos.append("Puntaje de reputación negativo en VirusTotal (%d), según reportes de la comunidad." % reputacion)

    return {
        "disponible": True,
        "encontrado": True,
        "maliciosos": maliciosos,
        "sospechosos": sospechosos,
        "total_motores": total_motores,
        "reputacion": reputacion,
        "categorias": categorias,
        "motores_marcaron": motores_marcaron[:8],
        "limpio": maliciosos == 0 and sospechosos == 0 and total_motores > 0,
        "hallazgos": hallazgos,
    }
