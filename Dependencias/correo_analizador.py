import joblib
import pandas as pd
import math
import re
import os
import sys

# ─── PATH propio ───
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from correoconnect       import descargar_correos
from correoextrator      import extraer_features_correo
from correofeaturestexto import extraer_features_texto_avanzadas

UMBRAL = 0.4

# ─── RUTAS ABSOLUTAS a los modelos ───
_base     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_mods_dir = os.path.join(_base, 'Modelos')
_csv_dir  = os.path.join(_base, 'Csv')

modelo   = joblib.load(os.path.join(_mods_dir, 'modelo_correos.pkl'))
features = joblib.load(os.path.join(_mods_dir, 'features_correos.pkl'))

# ─── CARGAR EMPRESAS LEGÍTIMAS ───
def _cargar_empresas():
    ruta = os.path.join(_csv_dir, 'empresas_legitimas.csv')
    try:
        df = pd.read_csv(ruta)
        dominios = set()
        for d in df['dominio'].dropna():
            d = str(d).strip().lower()
            partes = d.split('.')
            if len(partes) >= 2:
                dominios.add('.'.join(partes[-2:]))
            dominios.add(d)
        print(f"Empresas legítimas cargadas: {len(dominios)} dominios")
        return dominios
    except Exception as e:
        print(f"No se pudo cargar empresas_legitimas.csv: {e}")
        return set()

DOMINIOS_LEGITIMOS = _cargar_empresas()

def calcular_entropia(texto):
    if not texto:
        return 0.0
    freq = {}
    for c in texto:
        freq[c] = freq.get(c, 0) + 1
    e = 0.0
    for f in freq.values():
        p = f / len(texto)
        e -= p * math.log2(p)
    return round(e, 4)

def extraer_dominio(de_str):
    if not de_str:
        return ''
    match = re.search(r'@([\w\.\-]+)', de_str.lower())
    if not match:
        return ''
    return match.group(1).strip()

def dominio_es_legitimo(dominio):
    if not dominio:
        return False

    # comprobación exacta
    if dominio in DOMINIOS_LEGITIMOS:
        return True

    # comprobación por dominio base (subdominio.empresa.com → empresa.com)
    partes = dominio.split('.')
    if len(partes) >= 2:
        base = '.'.join(partes[-2:])
        if base in DOMINIOS_LEGITIMOS:
            return True

    return False

def _alertas(f):
    alertas = []
    if f.get('n_spam_palabras_es', 0) > 0:
        alertas.append(f"Palabras spam español: {f['n_spam_palabras_es']}")
    if f.get('n_spam_palabras_en', 0) > 2:
        alertas.append(f"Palabras spam inglés: {f['n_spam_palabras_en']}")
    if f.get('n_urls_texto', 0) > 0:
        alertas.append(f"URLs detectadas: {f['n_urls_texto']}")
    if f.get('n_patrones_phishing', 0) > 0:
        alertas.append(f"Patrones phishing: {f['n_patrones_phishing']}")
    if f.get('n_simbolos_dinero', 0) > 0:
        alertas.append(f"Símbolos monetarios: {f['n_simbolos_dinero']}")
    if f.get('reply_to_distinto', 0):
        alertas.append("Reply-To distinto al remitente")
    if f.get('pixel_tracking', 0) > 0:
        alertas.append(f"Píxeles de rastreo: {f['pixel_tracking']}")
    if f.get('combo_spam_dinero', 0):
        alertas.append("COMBO: spam + dinero")
    if f.get('combo_phishing_url', 0):
        alertas.append("COMBO: phishing + URL sospechosa")
    return alertas

def analizar_correo(correo):
    de_str  = correo.get('de', '')
    dominio = extraer_dominio(de_str)

    # ── WHITELIST — dominio en lista de empresas legítimas ──
    if dominio_es_legitimo(dominio):
        return {
            'asunto':    correo.get('asunto', ''),
            'de':        de_str,
            'fecha':     correo.get('fecha', ''),
            'score':     0.02,
            'veredicto': 'LEGÍTIMO',
            'alertas':   [f'Dominio verificado: {dominio}'],
        }

    # ── ANÁLISIS ML ──
    texto = correo.get('texto', '') or correo.get('html', '')

    f  = extraer_features_correo(correo)
    ft = extraer_features_texto_avanzadas(texto, asunto=correo.get('asunto', ''))
    f.update(ft)
    f['n_caracteres']   = len(texto)
    f['n_lineas']       = texto.count('\n')
    f['entropia_total'] = calcular_entropia(texto[:3000])

    X     = pd.DataFrame([f]).reindex(columns=features, fill_value=0)
    score = modelo.predict_proba(X)[0][1]

    if score >= UMBRAL:
        veredicto = 'SPAM/PHISHING'
    elif score >= 0.2:
        veredicto = 'SOSPECHOSO'
    else:
        veredicto = 'LEGÍTIMO'

    return {
        'asunto':    correo.get('asunto', ''),
        'de':        de_str,
        'fecha':     correo.get('fecha', ''),
        'score':     round(score, 4),
        'veredicto': veredicto,
        'alertas':   _alertas(f),
    }

def escanear_bandeja(limite=20, solo_no_leidos=False):
    print(f"\nDescargando {limite} correos...")
    correos = descargar_correos(limite=limite, solo_no_leidos=solo_no_leidos)

    print(f"Analizando {len(correos)} correos...\n")
    print("=" * 60)

    resultados = []
    for c in correos:
        r = analizar_correo(c)
        resultados.append(r)

        icono = {
            'SPAM/PHISHING': '⛔',
            'SOSPECHOSO':    '⚠ ',
            'LEGÍTIMO':      '✓ ',
        }.get(r['veredicto'], '? ')

        print(f"{icono} [{r['score']:.2f}] {r['asunto'][:50]}")
        print(f"     De: {r['de'][:50]}")
        if r['alertas']:
            for a in r['alertas']:
                print(f"     ! {a}")
        print()

    spam        = [r for r in resultados if r['veredicto'] == 'SPAM/PHISHING']
    sospechosos = [r for r in resultados if r['veredicto'] == 'SOSPECHOSO']
    legitimos   = [r for r in resultados if r['veredicto'] == 'LEGÍTIMO']

    print("=" * 60)
    print(f"  Total:       {len(resultados)}")
    print(f"  Spam:        {len(spam)}")
    print(f"  Sospechosos: {len(sospechosos)}")
    print(f"  Legítimos:   {len(legitimos)}")
    print("=" * 60)

    return resultados

if __name__ == '__main__':
    escanear_bandeja(limite=20)