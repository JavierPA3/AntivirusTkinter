import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
import os
import webbrowser
from datetime import datetime
from pathlib import Path
import importlib.util

# ─── IMPORTAR ANALIZADOR ARCHIVOS ───
ruta_modulo = os.path.join(os.path.dirname(os.path.abspath(__file__)), './Dependencias/analizador.py')
spec        = importlib.util.spec_from_file_location("analizador", ruta_modulo)
analizador  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analizador)

analizar_archivo   = analizador.analizar_archivo
EXTENSIONES_EXE    = analizador.EXTENSIONES_EXE
EXTENSIONES_CODIGO = analizador.EXTENSIONES_CODIGO

# ─── IMPORTAR ANALIZADOR CORREOS ───
try:
    ruta_correo = os.path.join(os.path.dirname(os.path.abspath(__file__)), './Dependencias/correo_analizador.py')
    spec2       = importlib.util.spec_from_file_location("correo_analizador", ruta_correo)
    correo_mod  = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(correo_mod)
    analizar_correo    = correo_mod.analizar_correo
    CORREOS_DISPONIBLE = True
except Exception as e:
    CORREOS_DISPONIBLE = False
    print(f"Módulo correos no disponible: {e}")

HISTORIAL_FILE = 'historial.json'

COLORES = {
    'MALWARE':       '#f38ba8',
    'SOSPECHOSO':    '#fab387',
    'LIMPIO':        '#a6e3a1',
    'NO SOPORTADO':  '#6c7086',
    'DESCONOCIDO':   '#6c7086',
    'SPAM/PHISHING': '#f38ba8',
    'LEGÍTIMO':      '#a6e3a1',
}

ICONOS = {
    'MALWARE':       '⛔',
    'SOSPECHOSO':    '⚠',
    'LIMPIO':        '✓',
    'NO SOPORTADO':  '—',
    'DESCONOCIDO':   '?',
    'SPAM/PHISHING': '⛔',
    'LEGÍTIMO':      '✓',
}

EXPLICACIONES = {
    'MALWARE':       'Este archivo ha sido clasificado como malicioso. Se recomienda eliminarlo o ponerlo en cuarentena inmediatamente.',
    'SOSPECHOSO':    'Este archivo tiene comportamientos inusuales pero no es malware confirmado. Revisa las señales detectadas antes de ejecutarlo.',
    'LIMPIO':        'No se han detectado señales maliciosas en este archivo.',
    'NO SOPORTADO':  'Este tipo de archivo no puede ser analizado por el motor actual.',
    'SPAM/PHISHING': 'Este correo ha sido clasificado como spam o phishing. No hagas clic en ningún enlace ni respondas.',
    'LEGÍTIMO':      'No se han detectado señales maliciosas en este correo.',
}

RECOMENDACIONES = {
    'MALWARE':       'Elimina o pon en cuarentena este archivo inmediatamente. No lo ejecutes bajo ningún concepto.',
    'SOSPECHOSO':    'No ejecutes este archivo hasta verificar su origen. Comprueba las señales detectadas.',
    'LIMPIO':        'El archivo parece seguro. Puedes ejecutarlo con normalidad.',
    'NO SOPORTADO':  'Este tipo de archivo no puede analizarse. Verifica su origen manualmente.',
    'SPAM/PHISHING': 'No respondas ni hagas clic en enlaces. Marca como spam y elimina el correo.',
    'LEGÍTIMO':      'El correo parece legítimo. Puedes leerlo con normalidad.',
}

PERFIL = {
    'nombre':    'Javier Postigo Arévalo',
    'rol':       'Desarrollador & Analista de Datos',
    'github':    'https://github.com/JavierPA3',
    'linkedin':  'https://www.linkedin.com/in/javierpostigoarevalo/',
    'portfolio': 'https://javierpa3.github.io/PersonalPorfolio/',
}


def cargar_historial():
    ruta = Path(HISTORIAL_FILE)
    if not ruta.exists():
        return []
    try:
        with open(ruta, 'r', encoding='utf-8') as f:
            contenido = f.read().strip()
            if not contenido:
                return []
            datos = json.loads(contenido)
            if datos and isinstance(datos[0], dict) and 'archivos' not in datos[0]:
                return []
            return datos
    except Exception:
        return []


def guardar_historial(h):
    with open(HISTORIAL_FILE, 'w', encoding='utf-8') as f:
        json.dump(h, f, ensure_ascii=False, indent=2)


# ─── VENTANA LOGIN CORREOS ───
class VentanaLoginCorreos:
    def __init__(self, parent, callback):
        self.callback = callback
        self.win = tk.Toplevel(parent)
        self.win.title("Conectar Gmail")
        self.win.geometry("480x380")
        self.win.resizable(False, False)
        self.win.configure(bg='#1e1e2e')
        self.win.grab_set()
        self._construir()

    def _construir(self):
        tk.Label(self.win,
            text="✉  Conectar con Gmail",
            font=('Segoe UI', 15, 'bold'),
            bg='#1e1e2e', fg='#cdd6f4'
        ).pack(anchor='w', padx=28, pady=(24, 4))

        tk.Label(self.win,
            text="Introduce tus credenciales de Gmail para analizar tu bandeja",
            font=('Segoe UI', 9),
            bg='#1e1e2e', fg='#6c7086'
        ).pack(anchor='w', padx=28)

        tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=28, pady=16)

        tk.Label(self.win,
            text="Correo Gmail",
            font=('Segoe UI', 9, 'bold'),
            bg='#1e1e2e', fg='#cdd6f4'
        ).pack(anchor='w', padx=28)

        self.entry_email = tk.Entry(self.win,
            font=('Segoe UI', 11),
            bg='#313244', fg='#cdd6f4',
            insertbackground='#cdd6f4',
            relief='flat', bd=0)
        self.entry_email.pack(fill='x', padx=28, pady=(4, 12), ipady=8)
        self.entry_email.insert(0, 'tucorreo@gmail.com')
        self.entry_email.bind('<FocusIn>', lambda e: self._limpiar(
            self.entry_email, 'tucorreo@gmail.com'))

        tk.Label(self.win,
            text="Contraseña de aplicación (16 caracteres)",
            font=('Segoe UI', 9, 'bold'),
            bg='#1e1e2e', fg='#cdd6f4'
        ).pack(anchor='w', padx=28)

        self.entry_clave = tk.Entry(self.win,
            font=('Segoe UI', 11),
            bg='#313244', fg='#cdd6f4',
            insertbackground='#cdd6f4',
            relief='flat', bd=0, show='●')
        self.entry_clave.pack(fill='x', padx=28, pady=(4, 4), ipady=8)

        enlace_frame = tk.Frame(self.win, bg='#1e1e2e')
        enlace_frame.pack(anchor='w', padx=28, pady=(4, 16))

        tk.Label(enlace_frame,
            text="¿No tienes contraseña de app?",
            font=('Segoe UI', 8),
            bg='#1e1e2e', fg='#6c7086'
        ).pack(side='left')

        lnk = tk.Label(enlace_frame,
            text=" Generarla aquí →",
            font=('Segoe UI', 8, 'underline'),
            bg='#1e1e2e', fg='#89b4fa',
            cursor='hand2')
        lnk.pack(side='left')
        lnk.bind('<Button-1>', lambda e: webbrowser.open(
            'https://myaccount.google.com/apppasswords'))

        self.lbl_error = tk.Label(self.win,
            text='',
            font=('Segoe UI', 9),
            bg='#1e1e2e', fg='#f38ba8')
        self.lbl_error.pack(anchor='w', padx=28)

        botones = tk.Frame(self.win, bg='#1e1e2e')
        botones.pack(fill='x', padx=28, pady=(12, 0))

        tk.Button(botones,
            text="Cancelar", command=self.win.destroy,
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 10), relief='flat',
            padx=14, pady=7, cursor='hand2'
        ).pack(side='right', padx=(8, 0))

        tk.Button(botones,
            text="Conectar", command=self._conectar,
            bg='#89b4fa', fg='#1e1e2e',
            font=('Segoe UI', 10, 'bold'), relief='flat',
            padx=14, pady=7, cursor='hand2'
        ).pack(side='right')

        self.entry_email.focus_set()
        self.win.bind('<Return>', lambda e: self._conectar())

    def _limpiar(self, entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, 'end')

    def _conectar(self):
        email = self.entry_email.get().strip()
        clave = self.entry_clave.get().strip()

        if not email or email == 'tucorreo@gmail.com':
            self.lbl_error.config(text='Introduce tu correo Gmail')
            return
        if '@gmail.com' not in email:
            self.lbl_error.config(text='El correo debe ser @gmail.com')
            return
        if len(clave.replace(' ', '')) < 16:
            self.lbl_error.config(text='La contraseña de app tiene 16 caracteres')
            return

        self.lbl_error.config(text='Verificando conexión...')
        self.win.update()

        try:
            import imaplib
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email, clave)
            mail.logout()
            self.win.destroy()
            self.callback(email, clave)
        except Exception as e:
            self.lbl_error.config(text=f'Error de conexión: {e}')


# ─── VENTANA LECTOR DE CORREO ───
class VentanaLectorCorreo:
    def __init__(self, parent, correo_raw, resultado_analisis):
        self.win = tk.Toplevel(parent)
        asunto   = correo_raw.get('asunto', '')[:50]
        self.win.title(f"Correo — {asunto}")
        self.win.geometry("720x580")
        self.win.configure(bg='#1e1e2e')
        self.win.grab_set()
        self._construir(correo_raw, resultado_analisis)

    def _construir(self, c, r):
        v     = r.get('veredicto', 'DESCONOCIDO')
        color = COLORES.get(v, '#6c7086')
        icono = ICONOS.get(v, '?')

        cab = tk.Frame(self.win, bg='#181825', pady=12)
        cab.pack(fill='x')

        tk.Label(cab,
            text=f"{icono}  {v}  —  Score: {r.get('score', 0):.2f}",
            font=('Segoe UI', 12, 'bold'),
            bg='#181825', fg=color
        ).pack(side='left', padx=16)

        tk.Button(cab,
            text="Cerrar", command=self.win.destroy,
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 9), relief='flat',
            padx=10, pady=4, cursor='hand2'
        ).pack(side='right', padx=16)

        meta = tk.Frame(self.win, bg='#1e1e2e', pady=8)
        meta.pack(fill='x', padx=16)

        for clave, valor in [
            ('De',     c.get('de',     '—')),
            ('Para',   c.get('para',   '—')),
            ('Asunto', c.get('asunto', '—')),
            ('Fecha',  c.get('fecha',  '—')),
        ]:
            fila = tk.Frame(meta, bg='#1e1e2e')
            fila.pack(fill='x', pady=1)
            tk.Label(fila,
                text=f"{clave}:",
                font=('Segoe UI', 9, 'bold'),
                bg='#1e1e2e', fg='#6c7086',
                width=8, anchor='w'
            ).pack(side='left')
            tk.Label(fila,
                text=str(valor)[:80],
                font=('Segoe UI', 9),
                bg='#1e1e2e', fg='#cdd6f4'
            ).pack(side='left')

        alertas = r.get('alertas', [])
        if alertas:
            tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=16, pady=4)
            af = tk.Frame(self.win, bg='#2a1828', pady=6)
            af.pack(fill='x', padx=16)
            for a in alertas:
                tk.Label(af,
                    text=f"  ⚠  {a}",
                    font=('Segoe UI', 9),
                    bg='#2a1828', fg='#fab387'
                ).pack(anchor='w', padx=8)

        tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=16, pady=8)

        tk.Label(self.win,
            text="CONTENIDO DEL CORREO",
            font=('Segoe UI', 8, 'bold'),
            bg='#1e1e2e', fg='#6c7086'
        ).pack(anchor='w', padx=16, pady=(0, 4))

        frame_txt = tk.Frame(self.win, bg='#181825')
        frame_txt.pack(fill='both', expand=True, padx=16, pady=(0, 16))

        sc = ttk.Scrollbar(frame_txt, orient='vertical')
        sc.pack(side='right', fill='y')

        txt = tk.Text(frame_txt,
            font=('Segoe UI', 9),
            bg='#181825', fg='#cdd6f4',
            insertbackground='#cdd6f4',
            relief='flat', wrap='word',
            yscrollcommand=sc.set,
            padx=12, pady=8)
        txt.pack(fill='both', expand=True)
        sc.config(command=txt.yview)

        from bs4 import BeautifulSoup
        html  = c.get('html',  '')
        texto = c.get('texto', '')

        if html:
            try:
                contenido = BeautifulSoup(html, 'html.parser').get_text(
                    separator='\n', strip=True)
            except Exception:
                contenido = texto
        else:
            contenido = texto

        txt.insert('1.0', contenido or 'Sin contenido')
        txt.config(state='disabled')


# ─── VENTANA SESIÓN ───
class VentanaSesion:
    def __init__(self, parent, sesion):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Sesión — {sesion['fecha']}")
        self.win.geometry("820x500")
        self.win.configure(bg='#1e1e2e')
        self.win.grab_set()
        self._construir(sesion)

    def _construir(self, sesion):
        header = tk.Frame(self.win, bg='#181825', pady=12)
        header.pack(fill='x')

        tk.Label(header,
            text=f"Sesión: {sesion['fecha']}",
            font=('Segoe UI', 13, 'bold'),
            bg='#181825', fg='#cdd6f4'
        ).pack(side='left', padx=16)

        resumen = (
            f"Total: {sesion['total']}   "
            f"Malware: {sesion['n_malware']}   "
            f"Sospechosos: {sesion['n_sospechosos']}   "
            f"Limpios: {sesion['n_limpios']}"
        )
        tk.Label(header,
            text=resumen,
            font=('Segoe UI', 9),
            bg='#181825', fg='#6c7086'
        ).pack(side='right', padx=16)

        cols  = ('icono', 'veredicto', 'archivo', 'score', 'motivo', 'alertas')
        frame = tk.Frame(self.win, bg='#181825')
        frame.pack(fill='both', expand=True, padx=16, pady=12)

        style = ttk.Style()
        style.configure('Sesion.Treeview',
            background='#181825', foreground='#cdd6f4',
            fieldbackground='#181825', rowheight=28,
            font=('Segoe UI', 9))
        style.configure('Sesion.Treeview.Heading',
            background='#313244', foreground='#89b4fa',
            font=('Segoe UI', 9, 'bold'), relief='flat')
        style.map('Sesion.Treeview',
            background=[('selected', '#45475a')])

        tree = ttk.Treeview(frame, columns=cols,
                            show='headings', style='Sesion.Treeview')

        tree.heading('icono',    text='')
        tree.heading('veredicto',text='Veredicto')
        tree.heading('archivo',  text='Archivo')
        tree.heading('score',    text='Score')
        tree.heading('motivo',   text='Motivo')
        tree.heading('alertas',  text='Señales')

        tree.column('icono',    width=30,  anchor='center')
        tree.column('veredicto',width=110, anchor='center')
        tree.column('archivo',  width=220)
        tree.column('score',    width=65,  anchor='center')
        tree.column('motivo',   width=180)
        tree.column('alertas',  width=180)

        for v, c in COLORES.items():
            tree.tag_configure(v, foreground=c)

        sc = ttk.Scrollbar(frame, orient='vertical',   command=tree.yview)
        sx = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=sc.set, xscrollcommand=sx.set)

        sc.pack(side='right',  fill='y')
        sx.pack(side='bottom', fill='x')
        tree.pack(fill='both', expand=True)

        for r in sesion.get('archivos', []):
            v       = r.get('veredicto', '?')
            alertas = ' | '.join(r.get('alertas', []))
            tree.insert('', 'end',
                values=(
                    ICONOS.get(v, '?'),
                    v,
                    Path(r.get('archivo', '')).name,
                    f"{r.get('score', 0):.2f}",
                    r.get('motivo', ''),
                    alertas or '—'
                ),
                tags=(v,)
            )

        tk.Button(self.win,
            text="Cerrar", command=self.win.destroy,
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 10), relief='flat',
            padx=16, pady=6, cursor='hand2'
        ).pack(anchor='e', padx=16, pady=(0, 12))


# ─── VENTANA DOCUMENTACIÓN ───
class VentanaDocumentacion:
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title("Documentación — Antivirus ML")
        self.win.geometry("700x580")
        self.win.configure(bg='#1e1e2e')
        self.win.grab_set()
        self._construir()

    def _construir(self):
        tk.Label(self.win,
            text="Documentación técnica",
            font=('Segoe UI', 15, 'bold'),
            bg='#1e1e2e', fg='#89b4fa'
        ).pack(anchor='w', padx=24, pady=(20, 4))

        tk.Label(self.win,
            text="Cómo detecta amenazas este antivirus",
            font=('Segoe UI', 10),
            bg='#1e1e2e', fg='#6c7086'
        ).pack(anchor='w', padx=24, pady=(0, 16))

        tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=24)

        canvas = tk.Canvas(self.win, bg='#1e1e2e', highlightthickness=0)
        sc     = ttk.Scrollbar(self.win, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=sc.set)
        sc.pack(side='right', fill='y')
        canvas.pack(fill='both', expand=True)

        frame = tk.Frame(canvas, bg='#1e1e2e')
        cw    = canvas.create_window((0, 0), window=frame, anchor='nw')
        frame.bind('<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',
            lambda e: canvas.itemconfig(cw, width=e.width))

        secciones = [
            ("CAPA 1 — Detección por firma (hash MD5)", "#f38ba8",
             "Cada archivo recibe su huella digital MD5 y se compara contra una base "
             "de datos de firmas de malware conocido. Si coincide, el veredicto es "
             "MALWARE inmediato con score 1.0 sin análisis adicional."),
            ("CAPA 2 — Señales individuales", "#fab387",
             "Se analizan funciones, imports y patrones en el código según el lenguaje:\n\n"
             "  Python:     eval(), exec(), subprocess, ctypes, winreg, base64\n"
             "  PowerShell: IEX, Invoke-Expression, -EncodedCommand, WebClient\n"
             "  Bash/Shell: curl | bash, wget | sh, crontab, chmod +x\n"
             "  JavaScript: eval(), atob(), document.write(), Function()\n"
             "  Batch:      certutil -decode, bitsadmin, schtasks, powershell -enc"),
            ("CAPA 3 — Correlación de señales", "#fab387",
             "Combos clave detectados:\n\n"
             "  Descarga + ejecución:      requests/curl + eval/exec/IEX\n"
             "  Base64 + ejecución:        base64 + eval/exec\n"
             "  Ofuscación + persistencia: base64/encoding + registro/crontab"),
            ("CAPA 4 — Features de contexto y ratio", "#a6e3a1",
             "Entropía, ratio señales/líneas, scripts disfrazados como .txt"),
            ("CAPA 5 — Modelo ML (archivos)", "#89b4fa",
             "Random Forest 500 árboles + calibración isotónica\n"
             "Dataset: ~11.000 archivos — Accuracy: 90% — Recall: 91%"),
            ("MÓDULO CORREOS — Detección spam/phishing", "#cba6f7",
             "Modelo independiente entrenado con 37.057 correos reales.\n\n"
             "  Datasets: español, inglés (Enron), fraud emails, phishing emails + manual\n"
             "  Features:  57 características por correo\n"
             "  Accuracy:  89%\n"
             "  Whitelist: 335 empresas verificadas (bypass directo)\n"
             "  Conexión:  IMAP Gmail con contraseña de aplicación"),
        ]

        for titulo, color, texto in secciones:
            tk.Label(frame, text=titulo,
                font=('Segoe UI', 10, 'bold'),
                bg='#1e1e2e', fg=color
            ).pack(anchor='w', padx=24, pady=(18, 4))
            tk.Frame(frame, bg=color, height=1).pack(fill='x', padx=24, pady=(0, 6))
            tk.Label(frame, text=texto,
                font=('Segoe UI', 9), bg='#1e1e2e', fg='#bac2de',
                wraplength=620, justify='left'
            ).pack(anchor='w', padx=28, pady=(0, 4))

        tk.Button(frame, text="Cerrar", command=self.win.destroy,
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 10), relief='flat',
            padx=16, pady=6, cursor='hand2'
        ).pack(anchor='e', padx=24, pady=20)


# ─── VENTANA PERFIL ───
class VentanaPerfil:
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title("Perfil — Javier Postigo Arévalo")
        self.win.geometry("460x400")
        self.win.resizable(False, False)
        self.win.configure(bg='#1e1e2e')
        self.win.grab_set()
        self._construir()

    def _construir(self):
        av_frame = tk.Frame(self.win, bg='#1e1e2e')
        av_frame.pack(pady=(28, 0))
        av = tk.Frame(av_frame, bg='#89b4fa', width=72, height=72)
        av.pack()
        av.pack_propagate(False)
        tk.Label(av, text="JP",
            font=('Segoe UI', 22, 'bold'),
            bg='#89b4fa', fg='#1e1e2e'
        ).place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(self.win, text=PERFIL['nombre'],
            font=('Segoe UI', 14, 'bold'),
            bg='#1e1e2e', fg='#cdd6f4'
        ).pack(pady=(12, 2))
        tk.Label(self.win, text=PERFIL['rol'],
            font=('Segoe UI', 10),
            bg='#1e1e2e', fg='#6c7086'
        ).pack()

        tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=40, pady=20)
        tk.Label(self.win,
            text="Proyecto de detección de malware y spam basado en Machine Learning.\n"
                 "Desarrollado con Python, scikit-learn y Tkinter.",
            font=('Segoe UI', 9), bg='#1e1e2e', fg='#bac2de',
            justify='center'
        ).pack(padx=32)
        tk.Frame(self.win, bg='#313244', height=1).pack(fill='x', padx=40, pady=20)

        enlaces = tk.Frame(self.win, bg='#1e1e2e')
        enlaces.pack()
        self._enlace(enlaces, "GitHub",    PERFIL['github'],    '#89b4fa')
        self._enlace(enlaces, "LinkedIn",  PERFIL['linkedin'],  '#5dade2')
        self._enlace(enlaces, "Portfolio", PERFIL['portfolio'], '#a6e3a1')

        tk.Button(self.win, text="Cerrar", command=self.win.destroy,
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 10), relief='flat',
            padx=16, pady=6, cursor='hand2'
        ).pack(pady=24)

    def _enlace(self, parent, texto, url, color):
        fila = tk.Frame(parent, bg='#1e1e2e')
        fila.pack(fill='x', padx=40, pady=4)
        tk.Label(fila, text=f"{texto}:",
            font=('Segoe UI', 9, 'bold'),
            bg='#1e1e2e', fg='#6c7086',
            width=9, anchor='w'
        ).pack(side='left')
        btn = tk.Label(fila, text=url,
            font=('Segoe UI', 9, 'underline'),
            bg='#1e1e2e', fg=color, cursor='hand2')
        btn.pack(side='left')
        btn.bind('<Button-1>', lambda e: webbrowser.open(url))


# ─── VENTANA PRINCIPAL ───
class AntivirusApp:
    def __init__(self, root):
        self.root           = root
        self.historial      = cargar_historial()
        self.analizando     = False
        self.resultados     = []
        self.correos_result = []
        self._correos_raw   = []
        self._gmail_email   = None
        self._gmail_clave   = None

        self.root.title("Antivirus ML")
        self.root.geometry("1100x700")
        self.root.minsize(900, 580)
        self.root.configure(bg='#1e1e2e')

        self._estilos()
        self._construir_ui()
        self._actualizar_historial()

    def _estilos(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('TNotebook',
            background='#1e1e2e', borderwidth=0)
        s.configure('TNotebook.Tab',
            background='#313244', foreground='#cdd6f4',
            padding=[16, 7], font=('Segoe UI', 10))
        s.map('TNotebook.Tab',
            background=[('selected', '#89b4fa')],
            foreground=[('selected', '#1e1e2e')])
        s.configure('Treeview',
            background='#181825', foreground='#cdd6f4',
            fieldbackground='#181825', rowheight=30,
            font=('Segoe UI', 9), borderwidth=0)
        s.configure('Treeview.Heading',
            background='#313244', foreground='#89b4fa',
            font=('Segoe UI', 9, 'bold'), relief='flat')
        s.map('Treeview', background=[('selected', '#45475a')])
        s.configure('TProgressbar',
            troughcolor='#313244', background='#89b4fa', borderwidth=0)

    def _construir_ui(self):
        # ── HEADER ──
        header = tk.Frame(self.root, bg='#181825', pady=14)
        header.pack(fill='x')

        tk.Label(header, text="⚡ Antivirus ML",
            font=('Segoe UI', 18, 'bold'),
            bg='#181825', fg='#cdd6f4'
        ).pack(side='left', padx=20)

        tk.Button(header, text="Perfil",
            command=lambda: VentanaPerfil(self.root),
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 9), relief='flat',
            padx=12, pady=4, cursor='hand2'
        ).pack(side='right', padx=6)

        tk.Button(header, text="Documentación",
            command=lambda: VentanaDocumentacion(self.root),
            bg='#313244', fg='#cdd6f4',
            font=('Segoe UI', 9), relief='flat',
            padx=12, pady=4, cursor='hand2'
        ).pack(side='right', padx=6)

        tk.Label(header,
            text="Motor: Random Forest  |  Archivos + Correos",
            font=('Segoe UI', 9),
            bg='#181825', fg='#6c7086'
        ).pack(side='right', padx=20)

        # ── ACCIONES ARCHIVOS ──
        acciones = tk.Frame(self.root, bg='#1e1e2e', pady=12)
        acciones.pack(fill='x', padx=20)

        self._btn(acciones, "Analizar archivo",
            '#89b4fa', self._sel_archivo).pack(side='left', padx=5)
        self._btn(acciones, "Analizar carpeta",
            '#89b4fa', self._sel_carpeta).pack(side='left', padx=5)
        self._btn(acciones, "Limpiar resultados",
            '#313244', self._limpiar, fg='#cdd6f4').pack(side='left', padx=5)

        self.lbl_progreso = tk.Label(acciones,
            text='', font=('Segoe UI', 9),
            bg='#1e1e2e', fg='#6c7086')
        self.lbl_progreso.pack(side='right', padx=10)

        # ── BARRA PROGRESO ──
        self.barra = ttk.Progressbar(self.root, mode='indeterminate')
        self.barra.pack(fill='x', padx=20, pady=(0, 8))

        # ── CUERPO ──
        cuerpo = tk.Frame(self.root, bg='#1e1e2e')
        cuerpo.pack(fill='both', expand=True, padx=20, pady=(0, 8))

        self.notebook = ttk.Notebook(cuerpo)
        self.notebook.pack(side='left', fill='both', expand=True)

        tab_res     = tk.Frame(self.notebook, bg='#181825')
        tab_correos = tk.Frame(self.notebook, bg='#181825')
        tab_hist    = tk.Frame(self.notebook, bg='#181825')

        self.notebook.add(tab_res,     text='  Archivos  ')
        self.notebook.add(tab_correos, text='  Correos  ')
        self.notebook.add(tab_hist,    text='  Historial  ')

        self._tabla_resultados(tab_res)
        self._tab_correos(tab_correos)
        self._tabla_historial(tab_hist)

        # ── PANEL LATERAL ──
        self.panel = tk.Frame(cuerpo, bg='#181825',
            width=320,
            highlightbackground='#313244',
            highlightthickness=1)
        self.panel.pack(side='right', fill='y', padx=(12, 0))
        self.panel.pack_propagate(False)
        self._construir_panel_lateral()

        # ── RESUMEN ──
        self.resumen_var = tk.StringVar(
            value='Selecciona un archivo o carpeta para analizar')
        tk.Label(self.root,
            textvariable=self.resumen_var,
            font=('Segoe UI', 9), bg='#1e1e2e', fg='#6c7086'
        ).pack(anchor='w', padx=24, pady=(0, 8))

    def _btn(self, parent, texto, color, cmd, fg='#1e1e2e'):
        return tk.Button(parent,
            text=texto, command=cmd,
            bg=color, fg=fg,
            font=('Segoe UI', 10, 'bold'),
            relief='flat', padx=14, pady=7,
            activebackground='#74c7ec',
            activeforeground='#1e1e2e',
            cursor='hand2', bd=0)

    # ─── TAB ARCHIVOS ───
    def _tabla_resultados(self, parent):
        cols = ('icono', 'veredicto', 'archivo', 'score', 'alertas')
        self.tree = ttk.Treeview(parent, columns=cols,
                                  show='headings', selectmode='browse')

        self.tree.heading('icono',     text='')
        self.tree.heading('veredicto', text='Veredicto')
        self.tree.heading('archivo',   text='Archivo')
        self.tree.heading('score',     text='Score')
        self.tree.heading('alertas',   text='Señales detectadas')

        self.tree.column('icono',    width=30,  anchor='center')
        self.tree.column('veredicto',width=110, anchor='center')
        self.tree.column('archivo',  width=260)
        self.tree.column('score',    width=65,  anchor='center')
        self.tree.column('alertas',  width=260)

        for v, c in COLORES.items():
            self.tree.tag_configure(v, foreground=c)

        sc = ttk.Scrollbar(parent, orient='vertical',   command=self.tree.yview)
        sx = ttk.Scrollbar(parent, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=sc.set, xscrollcommand=sx.set)

        sc.pack(side='right',  fill='y')
        sx.pack(side='bottom', fill='x')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_seleccion)

    # ─── TAB CORREOS ───
    def _tab_correos(self, parent):
        # ── CONTROLES ──
        ctrl = tk.Frame(parent, bg='#181825', pady=12)
        ctrl.pack(fill='x', padx=12)

        self.btn_login = tk.Button(ctrl,
            text="🔑  Conectar Gmail",
            command=self._abrir_login,
            bg='#cba6f7', fg='#1e1e2e',
            font=('Segoe UI', 10, 'bold'), relief='flat',
            padx=14, pady=7, cursor='hand2'
        )
        self.btn_login.pack(side='left', padx=(0, 10))

        self.lbl_conexion = tk.Label(ctrl,
            text="Sin conectar",
            font=('Segoe UI', 9),
            bg='#181825', fg='#6c7086'
        )
        self.lbl_conexion.pack(side='left', padx=(0, 12))

        tk.Frame(ctrl, bg='#313244', width=1, height=24).pack(side='left', padx=8)

        tk.Label(ctrl, text="Correos:",
            font=('Segoe UI', 9), bg='#181825', fg='#6c7086'
        ).pack(side='left', padx=(8, 4))

        self.var_limite = tk.IntVar(value=10)
        tk.Spinbox(ctrl, from_=5, to=200, increment=5,
            textvariable=self.var_limite, width=4,
            bg='#313244', fg='#cdd6f4',
            insertbackground='#cdd6f4',
            relief='flat', font=('Segoe UI', 9)
        ).pack(side='left', padx=(0, 10))

        self.var_no_leidos = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl,
            text="Solo no leídos",
            variable=self.var_no_leidos,
            bg='#181825', fg='#cdd6f4',
            selectcolor='#313244',
            activebackground='#181825',
            activeforeground='#cdd6f4',
            font=('Segoe UI', 9)
        ).pack(side='left', padx=(0, 10))

        self.btn_escanear = tk.Button(ctrl,
            text="↻  Escanear",
            command=self._escanear_correos,
            bg='#313244', fg='#6c7086',
            font=('Segoe UI', 10, 'bold'), relief='flat',
            padx=14, pady=7, cursor='hand2',
            state='disabled'
        )
        self.btn_escanear.pack(side='left', padx=4)

        self._btn(ctrl, "Limpiar", '#313244',
            self._limpiar_correos, fg='#cdd6f4').pack(side='left', padx=4)

        self.lbl_correos = tk.Label(ctrl,
            text='', font=('Segoe UI', 9),
            bg='#181825', fg='#6c7086')
        self.lbl_correos.pack(side='right', padx=10)

        # ── TABLA ──
        cols = ('icono', 'veredicto', 'asunto', 'de', 'fecha', 'score')
        self.tree_correos = ttk.Treeview(parent, columns=cols,
                                          show='headings', selectmode='browse')

        self.tree_correos.heading('icono',    text='')
        self.tree_correos.heading('veredicto',text='Veredicto')
        self.tree_correos.heading('asunto',   text='Asunto')
        self.tree_correos.heading('de',       text='Remitente')
        self.tree_correos.heading('fecha',    text='Fecha')
        self.tree_correos.heading('score',    text='Score')

        self.tree_correos.column('icono',    width=30,  anchor='center')
        self.tree_correos.column('veredicto',width=120, anchor='center')
        self.tree_correos.column('asunto',   width=250)
        self.tree_correos.column('de',       width=180)
        self.tree_correos.column('fecha',    width=130)
        self.tree_correos.column('score',    width=65,  anchor='center')

        for v, c in COLORES.items():
            self.tree_correos.tag_configure(v, foreground=c)

        sc = ttk.Scrollbar(parent, orient='vertical',
                            command=self.tree_correos.yview)
        sx = ttk.Scrollbar(parent, orient='horizontal',
                            command=self.tree_correos.xview)
        self.tree_correos.configure(
            yscrollcommand=sc.set, xscrollcommand=sx.set)

        sc.pack(side='right',  fill='y')
        sx.pack(side='bottom', fill='x')
        self.tree_correos.pack(fill='both', expand=True)

        self.tree_correos.bind('<Double-1>',         self._abrir_lector)
        self.tree_correos.bind('<<TreeviewSelect>>', self._on_seleccion_correo)

        tk.Label(parent,
            text="Doble clic en un correo para leerlo completo",
            font=('Segoe UI', 8), bg='#181825', fg='#45475a'
        ).pack(anchor='w', padx=8, pady=(4, 0))

    # ─── TAB HISTORIAL ───
    def _tabla_historial(self, parent):
        cols = ('fecha', 'total', 'n_malware', 'n_sospechosos', 'n_limpios')
        self.tree_hist = ttk.Treeview(parent, columns=cols,
                                       show='headings', selectmode='browse')

        self.tree_hist.heading('fecha',         text='Fecha')
        self.tree_hist.heading('total',         text='Archivos')
        self.tree_hist.heading('n_malware',     text='Malware')
        self.tree_hist.heading('n_sospechosos', text='Sospechosos')
        self.tree_hist.heading('n_limpios',     text='Limpios')

        self.tree_hist.column('fecha',         width=180)
        self.tree_hist.column('total',         width=80,  anchor='center')
        self.tree_hist.column('n_malware',     width=90,  anchor='center')
        self.tree_hist.column('n_sospechosos', width=110, anchor='center')
        self.tree_hist.column('n_limpios',     width=90,  anchor='center')

        self.tree_hist.tag_configure('peligro',  foreground='#f38ba8')
        self.tree_hist.tag_configure('sospecha', foreground='#fab387')
        self.tree_hist.tag_configure('limpio',   foreground='#a6e3a1')

        sc = ttk.Scrollbar(parent, orient='vertical',
                            command=self.tree_hist.yview)
        sc.pack(side='right', fill='y')
        self.tree_hist.pack(fill='both', expand=True)

        tk.Label(parent,
            text="Doble clic para ver los archivos de esa sesión",
            font=('Segoe UI', 8), bg='#181825', fg='#45475a'
        ).pack(anchor='w', padx=8, pady=(4, 0))

        tk.Button(parent,
            text="Borrar historial", command=self._borrar_historial,
            bg='#313244', fg='#f38ba8',
            font=('Segoe UI', 9), relief='flat',
            padx=10, pady=4, cursor='hand2'
        ).pack(anchor='e', padx=8, pady=6)

        self.tree_hist.bind('<Double-1>', self._on_doble_clic_sesion)

    # ─── PANEL LATERAL ───
    def _construir_panel_lateral(self):
        tk.Label(self.panel,
            text="Detalle del análisis",
            font=('Segoe UI', 11, 'bold'),
            bg='#181825', fg='#89b4fa'
        ).pack(anchor='w', padx=14, pady=(14, 4))

        tk.Frame(self.panel, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=(0, 10))

        canvas = tk.Canvas(self.panel, bg='#181825', highlightthickness=0)
        sc     = ttk.Scrollbar(self.panel, orient='vertical',
                                command=canvas.yview)
        canvas.configure(yscrollcommand=sc.set)

        sc.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        self.frame_detalle = tk.Frame(canvas, bg='#181825')
        self.canvas_window = canvas.create_window(
            (0, 0), window=self.frame_detalle, anchor='nw')

        self.frame_detalle.bind('<Configure>',
            lambda e: canvas.configure(
                scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',
            lambda e: canvas.itemconfig(
                self.canvas_window, width=e.width))

        self._panel_vacio()

    def _panel_vacio(self):
        for w in self.frame_detalle.winfo_children():
            w.destroy()
        tk.Label(self.frame_detalle,
            text="Haz clic en un resultado\npara ver el detalle",
            font=('Segoe UI', 10), bg='#181825', fg='#45475a',
            justify='center'
        ).pack(pady=40)

    def _panel_detalle_archivo(self, r):
        for w in self.frame_detalle.winfo_children():
            w.destroy()

        v     = r['veredicto']
        color = COLORES.get(v, '#6c7086')
        icono = ICONOS.get(v, '?')

        tk.Label(self.frame_detalle,
            text=f"{icono}  {v}",
            font=('Segoe UI', 15, 'bold'),
            bg='#181825', fg=color
        ).pack(anchor='w', padx=14, pady=(10, 2))

        score = r['score']
        tk.Label(self.frame_detalle,
            text=f"Score de riesgo: {score:.2f}",
            font=('Segoe UI', 9), bg='#181825', fg='#6c7086'
        ).pack(anchor='w', padx=14)

        bf = tk.Frame(self.frame_detalle, bg='#313244', height=8)
        bf.pack(fill='x', padx=14, pady=(4, 12))
        bf.pack_propagate(False)
        tk.Frame(bf, bg=color,
            width=int(score * 100), height=8).pack(side='left')

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=4)
        self._seccion(self.frame_detalle, "Por qué este veredicto")
        tk.Label(self.frame_detalle,
            text=EXPLICACIONES.get(v, ''),
            font=('Segoe UI', 9), bg='#181825', fg='#bac2de',
            wraplength=270, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 10))

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=4)
        self._seccion(self.frame_detalle, "Información del archivo")
        self._fila_info(self.frame_detalle, "Nombre",
            Path(r['archivo']).name)
        self._fila_info(self.frame_detalle, "MD5",
            r.get('md5') or '—')
        self._fila_info(self.frame_detalle, "Tipo",
            r.get('extension', '—'))
        self._fila_info(self.frame_detalle, "Motivo",
            r.get('motivo', '—'))

        self._panel_alertas(r.get('alertas', []))

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=(10, 4))
        self._seccion(self.frame_detalle, "Recomendación")
        tk.Label(self.frame_detalle,
            text=RECOMENDACIONES.get(v, ''),
            font=('Segoe UI', 9), bg='#181825', fg='#bac2de',
            wraplength=270, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 16))

    def _panel_detalle_correo(self, r):
        for w in self.frame_detalle.winfo_children():
            w.destroy()

        v     = r['veredicto']
        color = COLORES.get(v, '#6c7086')
        icono = ICONOS.get(v, '?')

        tk.Label(self.frame_detalle,
            text=f"{icono}  {v}",
            font=('Segoe UI', 15, 'bold'),
            bg='#181825', fg=color
        ).pack(anchor='w', padx=14, pady=(10, 2))

        score = r['score']
        tk.Label(self.frame_detalle,
            text=f"Score de riesgo: {score:.2f}",
            font=('Segoe UI', 9), bg='#181825', fg='#6c7086'
        ).pack(anchor='w', padx=14)

        bf = tk.Frame(self.frame_detalle, bg='#313244', height=8)
        bf.pack(fill='x', padx=14, pady=(4, 12))
        bf.pack_propagate(False)
        tk.Frame(bf, bg=color,
            width=int(score * 100), height=8).pack(side='left')

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=4)
        self._seccion(self.frame_detalle, "Por qué este veredicto")
        tk.Label(self.frame_detalle,
            text=EXPLICACIONES.get(v, ''),
            font=('Segoe UI', 9), bg='#181825', fg='#bac2de',
            wraplength=270, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 10))

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=4)
        self._seccion(self.frame_detalle, "Información del correo")
        self._fila_info(self.frame_detalle, "Asunto",
            r.get('asunto', '—')[:60])
        self._fila_info(self.frame_detalle, "De",
            r.get('de', '—')[:60])
        self._fila_info(self.frame_detalle, "Fecha",
            r.get('fecha', '—')[:30])

        self._panel_alertas(r.get('alertas', []))

        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=(10, 4))
        self._seccion(self.frame_detalle, "Recomendación")
        tk.Label(self.frame_detalle,
            text=RECOMENDACIONES.get(v, ''),
            font=('Segoe UI', 9), bg='#181825', fg='#bac2de',
            wraplength=270, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 16))

    def _panel_alertas(self, alertas):
        tk.Frame(self.frame_detalle, bg='#313244', height=1).pack(
            fill='x', padx=14, pady=(10, 4))
        self._seccion(self.frame_detalle,
            f"Señales detectadas ({len(alertas)})")

        if alertas:
            for alerta in alertas:
                fila = tk.Frame(self.frame_detalle, bg='#181825')
                fila.pack(fill='x', padx=14, pady=2)
                tk.Label(fila, text="!",
                    font=('Segoe UI', 9, 'bold'),
                    bg='#181825', fg='#fab387', width=2
                ).pack(side='left')
                tk.Label(fila, text=alerta,
                    font=('Segoe UI', 9),
                    bg='#181825', fg='#cdd6f4',
                    wraplength=240, justify='left'
                ).pack(side='left', anchor='w')
        else:
            tk.Label(self.frame_detalle,
                text="Ninguna señal sospechosa detectada",
                font=('Segoe UI', 9), bg='#181825', fg='#45475a'
            ).pack(anchor='w', padx=14)

    def _seccion(self, parent, titulo):
        tk.Label(parent,
            text=titulo.upper(),
            font=('Segoe UI', 8, 'bold'),
            bg='#181825', fg='#6c7086'
        ).pack(anchor='w', padx=14, pady=(6, 2))

    def _fila_info(self, parent, clave, valor):
        fila = tk.Frame(parent, bg='#181825')
        fila.pack(fill='x', padx=14, pady=1)
        tk.Label(fila, text=f"{clave}:",
            font=('Segoe UI', 9), width=7,
            bg='#181825', fg='#6c7086', anchor='w'
        ).pack(side='left')
        tk.Label(fila, text=str(valor),
            font=('Segoe UI', 9),
            bg='#181825', fg='#cdd6f4',
            wraplength=200, justify='left', anchor='w'
        ).pack(side='left', fill='x', expand=True)

    # ─── LOGIN CORREOS ───
    def _abrir_login(self):
        VentanaLoginCorreos(self.root, self._on_login_ok)

    def _on_login_ok(self, email, clave):
        self._gmail_email = email
        self._gmail_clave = clave
        self.lbl_conexion.config(text=f"✓  {email}", fg='#a6e3a1')
        self.btn_login.config(
            text="🔑  Cambiar cuenta",
            bg='#313244', fg='#cdd6f4')
        self.btn_escanear.config(
            state='normal',
            bg='#89b4fa', fg='#1e1e2e')
        # carga automática al conectar
        self.var_limite.set(10)
        self._escanear_correos()

    # ─── LECTOR ───
    def _abrir_lector(self, event):
        sel = self.tree_correos.selection()
        if not sel:
            return
        idx = self.tree_correos.index(sel[0])
        if idx < len(self._correos_raw) and idx < len(self.correos_result):
            VentanaLectorCorreo(
                self.root,
                self._correos_raw[idx],
                self.correos_result[idx]
            )

    # ─── EVENTOS CORREOS ───
    def _on_seleccion_correo(self, event):
        sel = self.tree_correos.selection()
        if not sel:
            return
        idx = self.tree_correos.index(sel[0])
        if idx < len(self.correos_result):
            self._panel_detalle_correo(self.correos_result[idx])

    def _escanear_correos(self):
        if self.analizando:
            return
        if not self._gmail_email or not self._gmail_clave:
            self._abrir_login()
            return

        self.analizando     = True
        self.correos_result = []
        self._correos_raw   = []

        for item in self.tree_correos.get_children():
            self.tree_correos.delete(item)

        self.barra.start(10)
        limite         = self.var_limite.get()
        solo_no_leidos = self.var_no_leidos.get()
        self.lbl_correos.config(
            text=f"Descargando {limite} correos...")

        threading.Thread(
            target=self._ejecutar_correos,
            args=(limite, solo_no_leidos), daemon=True
        ).start()

    def _ejecutar_correos(self, limite, solo_no_leidos):
        try:
            os.environ['GMAIL_USER']         = self._gmail_email
            os.environ['GMAIL_APP_PASSWORD'] = self._gmail_clave

            from Dependencias.correoconnect import descargar_correos
            correos = descargar_correos(
                limite=limite,
                solo_no_leidos=solo_no_leidos
            )

            for c in correos:
                r = analizar_correo(c)
                self._correos_raw.append(c)
                self.correos_result.append(r)
                self.root.after(0, self._agregar_fila_correo, r)

            self.root.after(0, self._finalizar_correos)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"No se pudo conectar con Gmail:\n{e}"
            ))
            self.root.after(0, self._finalizar_correos)

    def _agregar_fila_correo(self, r):
        v = r['veredicto']
        fecha = r.get('fecha', '')[:20]
        self.tree_correos.insert('', 'end',
            values=(
                ICONOS.get(v, '?'),
                v,
                r.get('asunto', '')[:60],
                r.get('de', '')[:50],
                fecha,
                f"{r.get('score', 0):.2f}",
            ),
            tags=(v,)
        )

    def _finalizar_correos(self):
        self.barra.stop()
        self.analizando = False

        spam  = sum(1 for r in self.correos_result
                    if r['veredicto'] == 'SPAM/PHISHING')
        sosp  = sum(1 for r in self.correos_result
                    if r['veredicto'] == 'SOSPECHOSO')
        legit = sum(1 for r in self.correos_result
                    if r['veredicto'] == 'LEGÍTIMO')
        total = len(self.correos_result)

        self.lbl_correos.config(
            text=f"Total: {total}  |  "
                 f"Spam: {spam}  |  "
                 f"Sosp: {sosp}  |  "
                 f"Legítimos: {legit}"
        )

        if spam > 0:
            messagebox.showwarning(
                "Spam detectado",
                f"Se detectaron {spam} correo(s) spam/phishing.\n"
                f"Haz clic en cada correo para ver el detalle."
            )

    def _limpiar_correos(self):
        for item in self.tree_correos.get_children():
            self.tree_correos.delete(item)
        self.correos_result = []
        self._correos_raw   = []
        self.lbl_correos.config(text='')
        self._panel_vacio()

    # ─── EVENTOS ARCHIVOS ───
    def _on_seleccion(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx < len(self.resultados):
            self._panel_detalle_archivo(self.resultados[idx])

    def _sel_archivo(self):
        if self.analizando:
            return
        exts = ' '.join(f'*{e}' for e in EXTENSIONES_EXE | EXTENSIONES_CODIGO)
        ruta = filedialog.askopenfilename(
            title='Seleccionar archivo',
            filetypes=[('Soportados', exts), ('Todos', '*.*')]
        )
        if ruta:
            self._analizar_hilo([Path(ruta)])

    def _sel_carpeta(self):
        if self.analizando:
            return
        carpeta = filedialog.askdirectory(title='Seleccionar carpeta')
        if not carpeta:
            return
        ignorar  = {'.git', '__pycache__', '.idea', 'node_modules', '.venv'}
        archivos = []
        for raiz, dirs, ficheros in os.walk(carpeta):
            dirs[:] = [d for d in dirs if d not in ignorar]
            for nombre in ficheros:
                ext = Path(nombre).suffix.lower()
                if ext in EXTENSIONES_EXE | EXTENSIONES_CODIGO:
                    archivos.append(Path(raiz) / nombre)
        if not archivos:
            messagebox.showinfo(
                "Sin archivos",
                "No se encontraron archivos soportados.")
            return
        self._analizar_hilo(archivos)

    def _analizar_hilo(self, archivos):
        self.analizando = True
        self.resultados = []
        self.barra.start(10)
        self.lbl_progreso.config(
            text=f"Analizando {len(archivos)} archivo(s)...")
        threading.Thread(
            target=self._ejecutar, args=(archivos,), daemon=True
        ).start()

    def _ejecutar(self, archivos):
        for ruta in archivos:
            r = analizar_archivo(ruta)
            self.resultados.append(r)
            self.root.after(0, self._agregar_fila, r)
        self.root.after(0, self._finalizar)

    def _agregar_fila(self, r):
        v       = r['veredicto']
        alertas = ' | '.join(r.get('alertas', []))
        self.tree.insert('', 'end',
            values=(
                ICONOS.get(v, '?'),
                v,
                Path(r['archivo']).name,
                f"{r['score']:.2f}",
                alertas or '—'
            ),
            tags=(v,)
        )

    def _finalizar(self):
        self.barra.stop()
        self.analizando = False
        self.lbl_progreso.config(text='')

        n_malware     = sum(1 for r in self.resultados
                            if r['veredicto'] == 'MALWARE')
        n_sospechosos = sum(1 for r in self.resultados
                            if r['veredicto'] == 'SOSPECHOSO')
        n_limpios     = sum(1 for r in self.resultados
                            if r['veredicto'] == 'LIMPIO')
        total         = len(self.resultados)

        self.resumen_var.set(
            f"Total: {total}   |   Malware: {n_malware}   |   "
            f"Sospechosos: {n_sospechosos}   |   Limpios: {n_limpios}"
        )

        sesion = {
            'fecha':         datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total':         total,
            'n_malware':     n_malware,
            'n_sospechosos': n_sospechosos,
            'n_limpios':     n_limpios,
            'archivos':      self.resultados,
        }
        self.historial.append(sesion)
        guardar_historial(self.historial)
        self._actualizar_historial()

        if n_malware > 0:
            messagebox.showwarning(
                "Malware detectado",
                f"Se encontraron {n_malware} archivo(s) malicioso(s).\n"
                f"Haz clic en cada resultado para ver el detalle."
            )

    def _limpiar(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.resultados = []
        self.resumen_var.set('')
        self._panel_vacio()

    # ─── HISTORIAL ───
    def _actualizar_historial(self):
        for item in self.tree_hist.get_children():
            self.tree_hist.delete(item)
        for sesion in reversed(self.historial):
            n_m = sesion.get('n_malware', 0)
            n_s = sesion.get('n_sospechosos', 0)
            tag = ('peligro' if n_m > 0
                   else 'sospecha' if n_s > 0
                   else 'limpio')
            self.tree_hist.insert('', 'end',
                values=(
                    sesion.get('fecha', ''),
                    sesion.get('total', 0),
                    n_m, n_s,
                    sesion.get('n_limpios', 0),
                ),
                tags=(tag,)
            )

    def _on_doble_clic_sesion(self, event):
        sel = self.tree_hist.selection()
        if not sel:
            return
        idx      = self.tree_hist.index(sel[0])
        idx_real = len(self.historial) - 1 - idx
        if 0 <= idx_real < len(self.historial):
            VentanaSesion(self.root, self.historial[idx_real])

    def _borrar_historial(self):
        if messagebox.askyesno("Confirmar", "¿Borrar todo el historial?"):
            self.historial = []
            guardar_historial(self.historial)
            self._actualizar_historial()


# ─── MAIN ───
if __name__ == '__main__':
    root = tk.Tk()
    app  = AntivirusApp(root)
    root.mainloop()