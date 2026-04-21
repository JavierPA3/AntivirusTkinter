import re

PALABRAS_SPAM_ES = [
    'gratis', 'gana', 'dinero', 'premio', 'ganador', 'oferta',
    'descuento', 'urgente', 'inmediato', 'click', 'haz clic',
    'compra', 'venta', 'beneficio', 'inversión', 'bitcoin',
    'crypto', 'pharma', 'farmacia', 'medicamento', 'pastilla',
    'viagra', 'cialis', 'adelgazar', 'perder peso', 'casino',
    'apuesta', 'lotería', 'herencia', 'transferencia', 'banco',
    'cuenta bloqueada', 'verificar', 'contraseña', 'password',
    'suspended', 'bloqueado', 'vencido', 'caducado', 'renovar',
    'factura', 'pago', 'reembolso', 'devolución', 'reclamación',
    'préstamo', 'crédito', 'hipoteca', 'deuda', 'sanción',
    'hacienda', 'agencia tributaria', 'multa', 'expediente',
    'nigeria', 'príncipe', 'herencia millonaria', 'trabajo desde casa',
    'ingresos extra', 'ganar dinero', 'sin esfuerzo', 'millonario',
    'gánate', 'exclusivo', 'limitado', 'garantizado', 'increíble',
    'no te lo pierdas', 'actúa ahora', 'caduca', 'expira',
    'darse de baja', 'cancelar suscripción', 'click aquí',
]

PALABRAS_SPAM_EN = [
    'free', 'win', 'winner', 'prize', 'cash', 'money', 'offer',
    'discount', 'urgent', 'click', 'buy', 'sale', 'cheap',
    'viagra', 'cialis', 'pharmacy', 'pills', 'weight loss',
    'casino', 'bet', 'lottery', 'inheritance', 'transfer',
    'account suspended', 'verify', 'password', 'bank',
    'invoice', 'payment', 'refund', 'claim', 'loan', 'credit',
    'mortgage', 'debt', 'nigeria', 'prince', 'work from home',
    'extra income', 'make money', 'no effort', 'millionaire',
    'guaranteed', 'limited time', 'act now', 'expire',
    'unsubscribe', 'opt out', 'remove', 'exclusive', 'incredible',
    'you have been selected', 'congratulations', 'dear friend',
    'confidential', 'beneficiary', 'next of kin', 'fund transfer',
    'million dollars', 'urgent assistance', 'god bless',
    'click here', 'click below', 'visit our website',
    'order now', 'buy now', 'sign up', 'log in', 'verify now',
]

# En correo_features_texto.py — quita ese patrón problemático
PATRONES_PHISHING = [
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'\.ru/|\.cn/|\.tk/|\.ml/|\.ga/|\.cf/',
    r'bit\.ly|tinyurl|goo\.gl|ow\.ly|shorturl',
    r'\$\s*\d+|\d+\s*\$|€\s*\d+|\d+\s*€',
    r'\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}',
    r'http[s]?://[^\s]{50,}',
    r'verify.*account|account.*verify',
    r'confirm.*identity|identity.*confirm',
    r'update.*information|information.*update',
    r'suspended.*account|account.*suspended',
    r'click.*link|link.*click',
]

def extraer_features_texto_avanzadas(texto, asunto=''):
    texto_completo = f"{asunto} {texto}".lower()
    f = {}

    # ── palabras spam español ──
    f['n_spam_palabras_es'] = sum(
        1 for p in PALABRAS_SPAM_ES if p.lower() in texto_completo
    )

    # ── palabras spam inglés ──
    f['n_spam_palabras_en'] = sum(
        1 for p in PALABRAS_SPAM_EN if p.lower() in texto_completo
    )

    # ── patrones phishing ──
    f['n_patrones_phishing'] = sum(
        len(re.findall(p, texto_completo, re.IGNORECASE))
        for p in PATRONES_PHISHING
    )

    # ── ratio mayúsculas ──
    letras = [c for c in texto if c.isalpha()]
    f['ratio_mayusculas'] = round(
        sum(1 for c in letras if c.isupper()) / max(len(letras), 1), 4
    )

    # ── signos ──
    f['n_exclamaciones']   = texto.count('!')
    f['n_interrogaciones'] = texto.count('?')

    # ── símbolos monetarios ──
    f['n_simbolos_dinero'] = len(re.findall(
        r'[$€£¥]|\d+\s*euros?|\d+\s*dollars?|\d+\s*€|\d+\s*\$',
        texto_completo
    ))

    # ── teléfonos ──
    f['n_telefonos'] = len(re.findall(r'\b\d{9,}\b|\+\d{10,}', texto))

    # ── porcentajes ──
    f['n_porcentajes'] = len(re.findall(r'\d+\s*%', texto))

    # ── palabras en mayúsculas ──
    palabras = texto.split()
    f['n_palabras_mayusculas'] = sum(
        1 for p in palabras if p.isupper() and len(p) > 2
    )

    # ── longitud asunto ──
    f['asunto_longitud_chars'] = len(asunto)

    # ── URLs en texto plano ──
    f['n_urls_texto'] = len(re.findall(r'https?://\S+', texto))

    # ── palabras de acción inmediata ──
    accion = ['click', 'here', 'now', 'today', 'immediately', 'urgent',
               'aquí', 'ahora', 'hoy', 'inmediatamente', 'urgente']
    f['n_palabras_accion'] = sum(
        1 for p in accion if p in texto_completo
    )

    # ── saludos genéricos de phishing ──
    saludos = ['dear friend', 'dear customer', 'dear user', 'dear sir',
               'estimado cliente', 'estimado usuario', 'querido amigo']
    f['n_saludos_genericos'] = sum(
        1 for s in saludos if s in texto_completo
    )

    # ── combos ──
    f['combo_spam_dinero'] = int(
        f['n_spam_palabras_es'] + f['n_spam_palabras_en'] > 0
        and f['n_simbolos_dinero'] > 0
    )
    f['combo_urgencia_accion'] = int(
        f['n_spam_palabras_es'] + f['n_spam_palabras_en'] > 2
        and f['n_exclamaciones'] > 0
    )
    f['combo_phishing_url'] = int(
        f['n_patrones_phishing'] > 0
        and f['n_urls_texto'] > 0
    )
    f['combo_saludo_url'] = int(
        f['n_saludos_genericos'] > 0
        and f['n_urls_texto'] > 0
    )

    return f