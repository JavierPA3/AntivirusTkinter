import re
import math
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ─── PALABRAS DE URGENCIA / PHISHING ───
PALABRAS_URGENCIA = [
    'urgente', 'urgent', 'inmediatamente', 'immediately', 'suspendido',
    'suspended', 'verificar', 'verify', 'confirmar', 'confirm',
    'actualizar', 'update', 'vencido', 'expired', 'bloqueado', 'blocked',
    'limitado', 'limited', 'acción requerida', 'action required',
    'cuenta bloqueada', 'account suspended', 'click here', 'haz clic',
    'premio', 'prize', 'ganador', 'winner', 'gratis', 'free', 'oferta',
    'offer', 'descuento', 'discount', 'password', 'contraseña',
    'login', 'iniciar sesión', 'bank', 'banco', 'paypal', 'bitcoin',
    'crypto', 'invoice', 'factura', 'refund', 'reembolso',
]

DOMINIOS_SOSPECHOSOS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
    'adf.ly', 'shorturl.at', 'cutt.ly', 'rb.gy', 'is.gd', 'v.gd',
]

EXTENSIONES_PELIGROSAS = [
    '.exe', '.dll', '.vbs', '.js', '.bat', '.ps1', '.cmd',
    '.scr', '.pif', '.com', '.jar', '.msi', '.hta',
]

# ─── ENTROPÍA ───
def calcular_entropia(texto):
    if not texto:
        return 0.0
    freq = {}
    for c in texto:
        freq[c] = freq.get(c, 0) + 1
    entropia = 0.0
    for f in freq.values():
        p = f / len(texto)
        entropia -= p * math.log2(p)
    return round(entropia, 4)

# ─── EXTRAER URLs DEL HTML ───
def extraer_urls(html, texto):
    urls = set()

    # del HTML con BeautifulSoup
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all(['a', 'img', 'form', 'iframe', 'script']):
                href = tag.get('href') or tag.get('src') or tag.get('action', '')
                if href and href.startswith('http'):
                    urls.add(href)
        except Exception:
            pass

    # del texto plano con regex
    patron_url = r'https?://[^\s<>"\'()]+'
    for url in re.findall(patron_url, texto or ''):
        urls.add(url)

    return list(urls)

# ─── ANALIZAR REMITENTE ───
def analizar_remitente(de_str):
    resultado = {
        'nombre':          '',
        'email':           '',
        'dominio':         '',
        'nombre_vs_dominio_distinto': 0,
    }

    if not de_str:
        return resultado

    # extraer email
    match = re.search(r'<([^>]+)>', de_str)
    if match:
        resultado['email']  = match.group(1).lower()
        resultado['nombre'] = de_str[:de_str.index('<')].strip().strip('"')
    else:
        resultado['email'] = de_str.strip().lower()

    # extraer dominio
    if '@' in resultado['email']:
        resultado['dominio'] = resultado['email'].split('@')[1]

    # ¿El nombre menciona una marca distinta al dominio?
    marcas = ['paypal', 'apple', 'google', 'amazon', 'microsoft', 'bank',
               'netflix', 'instagram', 'facebook', 'twitter', 'linkedin']
    nombre_lower  = resultado['nombre'].lower()
    dominio_lower = resultado['dominio'].lower()

    for marca in marcas:
        if marca in nombre_lower and marca not in dominio_lower:
            resultado['nombre_vs_dominio_distinto'] = 1
            break

    return resultado

# ─── EXTRAER FEATURES ───
def extraer_features_correo(correo):
    html     = correo.get('html',   '')
    texto    = correo.get('texto',  '')
    asunto   = correo.get('asunto', '')
    de_str   = correo.get('de',     '')
    reply_to = correo.get('reply_to', '')
    adjuntos = correo.get('adjuntos', [])
    cabeceras= correo.get('cabeceras', {})

    texto_completo = f"{asunto} {texto}"
    remitente      = analizar_remitente(de_str)
    urls           = extraer_urls(html, texto)

    # ── FEATURES REMITENTE ──
    f_nombre_vs_dominio    = remitente['nombre_vs_dominio_distinto']
    f_dominio_numeros      = int(bool(re.search(r'\d{3,}', remitente['dominio'])))
    f_dominio_guiones      = remitente['dominio'].count('-')
    f_subdominio_profundo  = remitente['dominio'].count('.') > 2

    # ── FEATURES ASUNTO ──
    f_asunto_longitud      = len(asunto)
    f_asunto_mayusculas    = sum(1 for c in asunto if c.isupper())
    f_asunto_exclamaciones = asunto.count('!')
    f_asunto_entropia      = calcular_entropia(asunto)
    f_asunto_urgencia      = sum(
        1 for p in PALABRAS_URGENCIA if p.lower() in asunto.lower()
    )

    # ── FEATURES URLs ──
    dominios_urls = []
    for url in urls:
        try:
            ext = tldextract.extract(url)
            dominios_urls.append(f"{ext.domain}.{ext.suffix}")
        except Exception:
            pass

    dominios_unicos        = set(dominios_urls)
    dominio_remitente      = remitente['dominio']

    f_n_urls               = len(urls)
    f_n_dominios_unicos    = len(dominios_unicos)
    f_n_urls_acortadas     = sum(1 for d in dominios_urls if d in DOMINIOS_SOSPECHOSOS)
    f_n_urls_externos      = sum(
        1 for d in dominios_urls if dominio_remitente and d != dominio_remitente
    )
    f_urls_text_distinto   = 0

    # detectar links donde el texto visible difiere de la URL real
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href      = a.get('href', '')
                link_text = a.get_text(strip=True)
                if (href.startswith('http') and
                    link_text.startswith('http') and
                    link_text not in href):
                    f_urls_text_distinto += 1
        except Exception:
            pass

    # ── FEATURES HTML ──
    f_tiene_html      = int(bool(html))
    f_html_longitud   = len(html)
    f_n_formularios   = 0
    f_n_inputs        = 0
    f_n_iframes       = 0
    f_n_scripts       = 0
    f_n_imagenes      = 0
    f_pixel_tracking  = 0
    f_ratio_texto_html= 0.0

    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')

            f_n_formularios = len(soup.find_all('form'))
            f_n_inputs      = len(soup.find_all('input'))
            f_n_iframes     = len(soup.find_all('iframe'))
            f_n_scripts     = len(soup.find_all('script'))
            f_n_imagenes    = len(soup.find_all('img'))

            # píxel de rastreo — imagen 1x1
            for img in soup.find_all('img'):
                w = img.get('width',  '')
                h = img.get('height', '')
                if str(w) == '1' and str(h) == '1':
                    f_pixel_tracking += 1

            # ratio texto visible / html total
            texto_visible = soup.get_text(separator=' ', strip=True)
            if f_html_longitud > 0:
                f_ratio_texto_html = round(len(texto_visible) / f_html_longitud, 4)

        except Exception:
            pass

    # ── FEATURES ADJUNTOS ──
    f_n_adjuntos           = len(adjuntos)
    f_adjunto_peligroso    = 0
    f_adjunto_doble_ext    = 0

    for nombre in adjuntos:
        nombre_lower = nombre.lower()
        for ext in EXTENSIONES_PELIGROSAS:
            if nombre_lower.endswith(ext):
                f_adjunto_peligroso += 1
        # doble extensión: factura.pdf.exe
        partes = nombre_lower.split('.')
        if len(partes) >= 3:
            f_adjunto_doble_ext += 1

    # ── FEATURES CABECERAS ──
    auth = cabeceras.get('authentication', '').lower()
    spf  = cabeceras.get('spf', '').lower()

    f_spf_falla  = int('fail' in spf  or 'fail' in auth)
    f_dkim_falla = int('dkim=fail' in auth)
    f_dmarc_falla= int('dmarc=fail' in auth)
    f_reply_to_distinto = int(
        bool(reply_to) and
        reply_to.lower() != de_str.lower() and
        len(reply_to) > 3
    )

    # ── FEATURES CONTENIDO ──
    f_n_palabras_urgencia  = sum(
        1 for p in PALABRAS_URGENCIA if p.lower() in texto_completo.lower()
    )
    f_entropia_texto       = calcular_entropia(texto[:2000] if texto else '')
    f_n_palabras           = len(texto_completo.split())

    # ── COMBOS ──
    f_combo_urgencia_link  = int(f_n_palabras_urgencia > 0 and f_n_urls > 0)
    f_combo_form_externo   = int(f_n_formularios > 0 and f_n_urls_externos > 0)
    f_combo_adjunto_urgencia = int(f_adjunto_peligroso > 0 and f_n_palabras_urgencia > 0)

    return {
        # remitente
        'nombre_vs_dominio_distinto': f_nombre_vs_dominio,
        'dominio_tiene_numeros':      f_dominio_numeros,
        'dominio_guiones':            f_dominio_guiones,
        'subdominio_profundo':        int(f_subdominio_profundo),
        # asunto
        'asunto_longitud':            f_asunto_longitud,
        'asunto_mayusculas':          f_asunto_mayusculas,
        'asunto_exclamaciones':       f_asunto_exclamaciones,
        'asunto_entropia':            f_asunto_entropia,
        'asunto_urgencia':            f_asunto_urgencia,
        # urls
        'n_urls':                     f_n_urls,
        'n_dominios_unicos':          f_n_dominios_unicos,
        'n_urls_acortadas':           f_n_urls_acortadas,
        'n_urls_externos':            f_n_urls_externos,
        'urls_text_distinto':         f_urls_text_distinto,
        # html
        'tiene_html':                 f_tiene_html,
        'html_longitud':              f_html_longitud,
        'n_formularios':              f_n_formularios,
        'n_inputs':                   f_n_inputs,
        'n_iframes':                  f_n_iframes,
        'n_scripts':                  f_n_scripts,
        'n_imagenes':                 f_n_imagenes,
        'pixel_tracking':             f_pixel_tracking,
        'ratio_texto_html':           f_ratio_texto_html,
        # adjuntos
        'n_adjuntos':                 f_n_adjuntos,
        'adjunto_peligroso':          f_adjunto_peligroso,
        'adjunto_doble_ext':          f_adjunto_doble_ext,
        # cabeceras
        'spf_falla':                  f_spf_falla,
        'dkim_falla':                 f_dkim_falla,
        'dmarc_falla':                f_dmarc_falla,
        'reply_to_distinto':          f_reply_to_distinto,
        # contenido
        'n_palabras_urgencia':        f_n_palabras_urgencia,
        'entropia_texto':             f_entropia_texto,
        'n_palabras':                 f_n_palabras,
        # combos
        'combo_urgencia_link':        f_combo_urgencia_link,
        'combo_form_externo':         f_combo_form_externo,
        'combo_adjunto_urgencia':     f_combo_adjunto_urgencia,
    }


if __name__ == '__main__':
    from Dependencias.correoconnect import descargar_correos
    import json

    correos = descargar_correos(limite=5)
    for c in correos:
        features = extraer_features_correo(c)
        print(f"\nDe: {c['de'][:50]}")
        print(f"Asunto: {c['asunto'][:50]}")
        print(f"Features relevantes:")
        print(f"  URLs:            {features['n_urls']}")
        print(f"  URLs externas:   {features['n_urls_externos']}")
        print(f"  URLs acortadas:  {features['n_urls_acortadas']}")
        print(f"  Formularios:     {features['n_formularios']}")
        print(f"  Palabras urgencia: {features['n_palabras_urgencia']}")
        print(f"  SPF falla:       {features['spf_falla']}")
        print(f"  Reply-To distinto: {features['reply_to_distinto']}")
        print(f"  Pixel tracking:  {features['pixel_tracking']}")
        print(f"  Adjunto peligroso: {features['adjunto_peligroso']}")