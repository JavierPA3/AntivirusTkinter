import imaplib
import email
import os
from email.header import decode_header
from dotenv import load_dotenv

load_dotenv()

GMAIL_USER     = os.getenv('GMAIL_USER')
GMAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')

def conectar():
    import os
    user     = os.environ.get('GMAIL_USER')     or os.getenv('GMAIL_USER')
    password = os.environ.get('GMAIL_APP_PASSWORD') or os.getenv('GMAIL_APP_PASSWORD')

    if not user or not password:
        raise ValueError("Credenciales Gmail no configuradas")

    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(user, password)
    return mail

def decodificar_cabecera(valor):
    if not valor:
        return ''
    partes = decode_header(valor)
    resultado = []
    for contenido, codificacion in partes:
        if isinstance(contenido, bytes):
            resultado.append(contenido.decode(codificacion or 'utf-8', errors='ignore'))
        else:
            resultado.append(contenido)
    return ' '.join(resultado)

def extraer_cuerpo(msg):
    html  = ''
    texto = ''
    if msg.is_multipart():
        for parte in msg.walk():
            tipo = parte.get_content_type()
            disp = str(parte.get('Content-Disposition', ''))
            if 'attachment' in disp:
                continue
            charset = parte.get_content_charset() or 'utf-8'
            try:
                contenido = parte.get_payload(decode=True).decode(charset, errors='ignore')
            except Exception:
                continue
            if tipo == 'text/html':
                html  += contenido
            elif tipo == 'text/plain':
                texto += contenido
    else:
        charset = msg.get_content_charset() or 'utf-8'
        try:
            contenido = msg.get_payload(decode=True).decode(charset, errors='ignore')
        except Exception:
            contenido = ''
        if msg.get_content_type() == 'text/html':
            html  = contenido
        else:
            texto = contenido
    return html, texto

def extraer_adjuntos(msg):
    adjuntos = []
    if msg.is_multipart():
        for parte in msg.walk():
            disp = str(parte.get('Content-Disposition', ''))
            if 'attachment' in disp:
                nombre = parte.get_filename()
                if nombre:
                    adjuntos.append(decodificar_cabecera(nombre))
    return adjuntos

def descargar_correos(carpeta='INBOX', limite=50, solo_no_leidos=False):
    print(f"Conectando a Gmail como {GMAIL_USER}...")
    mail = conectar()
    mail.select(carpeta)

    criterio = 'UNSEEN' if solo_no_leidos else 'ALL'
    _, ids   = mail.search(None, criterio)
    lista_ids = ids[0].split()

    # los más recientes primero
    lista_ids = lista_ids[::-1][:limite]

    print(f"Descargando {len(lista_ids)} correos...")

    correos = []
    for uid in lista_ids:
        try:
            _, data = mail.fetch(uid, '(RFC822)')
            msg     = email.message_from_bytes(data[0][1])

            html, texto = extraer_cuerpo(msg)
            adjuntos    = extraer_adjuntos(msg)

            correo = {
                'uid':        uid.decode(),
                'asunto':     decodificar_cabecera(msg.get('Subject',  '')),
                'de':         decodificar_cabecera(msg.get('From',     '')),
                'para':       decodificar_cabecera(msg.get('To',       '')),
                'fecha':      msg.get('Date', ''),
                'reply_to':   decodificar_cabecera(msg.get('Reply-To', '')),
                'html':       html,
                'texto':      texto,
                'adjuntos':   adjuntos,
                'cabeceras':  {
                    'received':      msg.get('Received',         ''),
                    'spf':           msg.get('Received-SPF',     ''),
                    'dkim':          msg.get('DKIM-Signature',   ''),
                    'authentication':msg.get('Authentication-Results', ''),
                },
            }
            correos.append(correo)
        except Exception as e:
            print(f"Error en correo {uid}: {e}")
            continue

    mail.logout()
    print(f"Descargados {len(correos)} correos")
    return correos


if __name__ == '__main__':
    correos = descargar_correos(limite=5)
    for c in correos:
        print(f"\nDe:     {c['de']}")
        print(f"Asunto: {c['asunto']}")
        print(f"Fecha:  {c['fecha']}")
        print(f"Adjuntos: {c['adjuntos']}")
        print(f"HTML: {len(c['html'])} chars")