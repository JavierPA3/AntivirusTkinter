import os
import sys
import re
import ast
import math
import hashlib
import joblib
import pandas as pd
from pathlib import Path

# ─── RUTAS ───
_dir      = os.path.dirname(os.path.abspath(__file__))
_base     = os.path.dirname(_dir)
_mods_dir = os.path.join(_base, 'Modelos')

if _dir not in sys.path:
    sys.path.insert(0, _dir)

# ─── CONFIGURACIÓN ───
UMBRAL_EXE    = 0.5
UMBRAL_CODIGO = 0.6

EXTENSIONES_EXE    = {'.exe', '.dll'}
EXTENSIONES_CODIGO = {'.py', '.ps1', '.js', '.sh', '.bat', '.vbs', '.txt'}

# ─── CARGAR MODELOS ───
try:
    modelo_exe = joblib.load(os.path.join(_mods_dir, 'modelo.pkl'))
    print("Modelo EXE cargado")
except Exception as e:
    modelo_exe = None
    print(f"AVISO: modelo.pkl no encontrado — {e}")

try:
    modelo_codigo   = joblib.load(os.path.join(_mods_dir, 'modelo_codigo.pkl'))
    features_codigo = joblib.load(os.path.join(_mods_dir, 'features_codigo.pkl'))
    print("Modelo codigo cargado")
except Exception as e:
    modelo_codigo   = None
    features_codigo = None
    print(f"AVISO: modelo_codigo.pkl no encontrado — {e}")

# ─── BASE DE DATOS DE FIRMAS ───
FIRMAS_CONOCIDAS = {
    "44d88612fea8a8f36de82e1278abb02f": "Worm.Conficker",
    "e44a0c2ea6e43de3a66f9c9b1b2d4f32": "Trojan.Generic",
}

# ─── HASH ───
def calcular_md5(ruta):
    with open(ruta, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

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

# ─── AST PYTHON ───
def analizar_ast(codigo):
    n_eval = n_exec = n_import = 0
    IMPORTS_SOSPECHOSOS = {'subprocess', 'socket', 'ctypes', 'winreg', 'marshal'}
    try:
        tree = ast.parse(codigo)
        for nodo in ast.walk(tree):
            if isinstance(nodo, ast.Call):
                if isinstance(nodo.func, ast.Name):
                    if nodo.func.id == 'eval': n_eval += 1
                    if nodo.func.id == 'exec': n_exec += 1
            if isinstance(nodo, ast.Import):
                for alias in nodo.names:
                    if alias.name in IMPORTS_SOSPECHOSOS:
                        n_import += 1
    except Exception:
        pass
    return n_eval, n_exec, n_import

# ─── PATRONES POR EXTENSIÓN ───
PATRONES = {
    '.py': [
        (r'eval\s*\(',                            'n_eval'),
        (r'exec\s*\(',                            'n_exec'),
        (r'base64',                               'n_base64'),
        (r'os\.system\s*\(',                      'n_os_system'),
        (r'subprocess',                           'n_subprocess'),
        (r'socket\.',                             'n_socket'),
        (r'requests\.',                           'n_requests'),
        (r'urllib',                               'n_urllib'),
        (r'ctypes',                               'n_ctypes'),
        (r'winreg',                               'n_winreg'),
        (r'marshal',                              'n_marshal'),
        (r'pickle\.loads',                        'n_pickle'),
        (r'__import__\s*\(',                      'n_import_dinamico'),
        (r'compile\s*\(',                         'n_compile'),
    ],
    '.ps1': [
        (r'Invoke-Expression|IEX',                'n_iex'),
        (r'EncodedCommand|-enc\b',                'n_encoded'),
        (r'WebClient|DownloadString|DownloadFile','n_webclient'),
        (r'base64',                               'n_base64'),
        (r'bypass',                               'n_bypass'),
        (r'Start-Process',                        'n_start_process'),
        (r'Set-ItemProperty.*Run',                'n_registro'),
        (r'Invoke-Mimikatz|mimikatz',             'n_mimikatz'),
    ],
    '.js': [
        (r'eval\s*\(',                            'n_eval'),
        (r'Function\s*\(',                        'n_function_dyn'),
        (r'atob\s*\(',                            'n_base64'),
        (r'XMLHttpRequest|fetch\s*\(',            'n_red'),
        (r'document\.write\s*\(',                 'n_doc_write'),
        (r'unescape\s*\(',                        'n_unescape'),
        (r'ActiveXObject',                        'n_activex'),
        (r'WScript',                              'n_wscript'),
        (r'MSXML2',                               'n_msxml'),
    ],
    '.sh': [
        (r'curl.+\|\s*(bash|sh)',                 'n_curl_pipe'),
        (r'wget.+\|\s*(bash|sh)',                 'n_wget_pipe'),
        (r'base64\s+-d',                          'n_base64'),
        (r'chmod\s+\+x',                          'n_chmod'),
        (r'crontab',                              'n_crontab'),
        (r'/etc/passwd|/etc/shadow',              'n_passwd'),
    ],
    '.bat': [
        (r'powershell.+-e(nc)?\b',                'n_ps_encoded'),
        (r'certutil.+-decode',                    'n_certutil'),
        (r'bitsadmin',                            'n_bitsadmin'),
        (r'schtasks',                             'n_schtasks'),
        (r'reg\s+add',                            'n_reg_add'),
    ],
    '.vbs': [
        (r'CreateObject\s*\(',                    'n_createobject'),
        (r'WScript\.Shell',                       'n_wscript_shell'),
        (r'WScript\.Run|Shell\s*\(',              'n_shell_run'),
        (r'Scripting\.FileSystemObject',          'n_fso'),
        (r'MSXML2\.XMLHTTP|WinHttp',              'n_http_vbs'),
        (r'\.Write\s*\(',                         'n_write'),
        (r'ExecuteStatement|Execute\s*\(',        'n_execute'),
        (r'eval\s*\(',                            'n_eval'),
        (r'Chr\s*\(',                             'n_chr'),
        (r'ChrW\s*\(',                            'n_chrw'),
        (r'Environ\s*\(',                         'n_environ'),
        (r'RegWrite|RegRead',                     'n_registro'),
        (r'base64',                               'n_base64'),
        (r'GetObject\s*\(',                       'n_getobject'),
        (r'winmgmts|WMI',                         'n_wmi'),
        (r'AutoRun|AutoOpen|Auto_Open',           'n_autorun'),
        (r'\.Run\s*\(',                           'n_run'),
        (r'taskkill|tasklist',                    'n_taskkill'),
        (r'cmd\.exe',                             'n_cmd'),
        (r'powershell',                           'n_powershell_vbs'),
    ],
    '.txt': [
        (r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', 'n_base64'),
        (r'IEX|Invoke-Expression',                'n_iex'),
        (r'eval\s*\(',                            'n_eval'),
        (r'exec\s*\(',                            'n_exec'),
        (r'http[s]?://\S+',                       'n_urls'),
        (r'cmd\.exe|powershell',                  'n_cmd'),
        (r'wget|curl',                            'n_wget_curl'),
        (r'base64',                               'n_base64_str'),
        (r'#!/bin/bash|#!/bin/sh',                'n_shebang'),
    ],
}

PATRON_DEFAULT = [
    (r'eval',   'n_eval'),
    (r'base64', 'n_base64'),
    (r'exec',   'n_exec'),
]

# ─── ALERTAS ───
ALERTAS_DESCRIPCION = {
    'n_eval':                        'eval() — ejecución dinámica de código',
    'n_exec':                        'exec() — ejecución dinámica de código',
    'n_base64':                      'base64 — posible ofuscación de payload',
    'n_subprocess':                  'subprocess — ejecución de procesos del sistema',
    'n_iex':                         'IEX/Invoke-Expression — ejecución dinámica PS',
    'n_encoded':                     'EncodedCommand — comando PowerShell codificado',
    'n_webclient':                   'WebClient — descarga desde internet',
    'n_ctypes':                      'ctypes — llamadas directas a DLLs de Windows',
    'n_winreg':                      'winreg — modificación del registro de Windows',
    'n_marshal':                     'marshal — deserialización peligrosa',
    'n_pickle':                      'pickle.loads — deserialización peligrosa',
    'n_curl_pipe':                   'curl | bash — descarga y ejecución directa',
    'n_wget_pipe':                   'wget | sh — descarga y ejecución directa',
    'n_crontab':                     'crontab — persistencia en Linux',
    'n_passwd':                      '/etc/passwd — acceso a credenciales del sistema',
    'n_ps_encoded':                  'powershell -enc — comando codificado en base64',
    'n_certutil':                    'certutil -decode — descarga encubierta Windows',
    'n_bitsadmin':                   'bitsadmin — descarga encubierta Windows',
    'n_schtasks':                    'schtasks — persistencia con tareas programadas',
    'n_reg_add':                     'reg add — modificación del registro Windows',
    'n_createobject':                'CreateObject() — creación de objeto COM sospechoso',
    'n_wscript_shell':               'WScript.Shell — acceso al shell de Windows',
    'n_shell_run':                   'Shell/WScript.Run — ejecución de procesos',
    'n_fso':                         'FileSystemObject — manipulación del sistema de archivos',
    'n_http_vbs':                    'MSXML2/WinHttp — petición HTTP desde VBScript',
    'n_execute':                     'Execute/ExecuteStatement — ejecución dinámica VBS',
    'n_chr':                         'Chr() — ofuscación de caracteres en VBScript',
    'n_chrw':                        'ChrW() — ofuscación Unicode en VBScript',
    'n_environ':                     'Environ() — lectura de variables de entorno',
    'n_getobject':                   'GetObject() — acceso a objetos del sistema',
    'n_wmi':                         'WMI/winmgmts — acceso a WMI del sistema',
    'n_autorun':                     'AutoRun/AutoOpen — ejecución automática al abrir',
    'n_powershell_vbs':              'PowerShell desde VBScript — cadena de ejecución',
    'n_taskkill':                    'taskkill — terminación de procesos del sistema',
    'n_activex':                     'ActiveXObject — objeto COM desde JavaScript',
    'n_wscript':                     'WScript — acceso al intérprete de Windows',
    'n_msxml':                       'MSXML2 — petición HTTP desde JScript',
    'n_function_dyn':                'Function() — creación dinámica de función JS',
    'n_doc_write':                   'document.write() — escritura dinámica en DOM',
    'n_unescape':                    'unescape() — decodificación de strings ofuscados',
    'combo_descarga_ejecucion':      'COMBO CRÍTICO: descarga + ejecución dinámica',
    'combo_base64_ejecucion':        'COMBO CRÍTICO: base64 + ejecución de código',
    'combo_ofuscacion_persistencia': 'COMBO CRÍTICO: ofuscación + persistencia',
    'n_vbs_combo_descarga':          'COMBO VBS: descarga HTTP + ejecución shell',
    'n_vbs_combo_ejecucion':         'COMBO VBS: ofuscación Chr() + Execute()',
    'n_urls':                        'URLs detectadas en texto plano',
    'n_cmd':                         'cmd.exe/powershell en texto plano',
    'n_wget_curl':                   'wget/curl en texto plano',
    'n_shebang':                     'shebang detectado — posible script disfrazado',
    'es_script_disfrazado':          'archivo .txt con estructura de script',
    'n_base64_largo':                'bloque base64 largo — posible payload oculto',
    'n_import_sospechoso':           'import de módulo peligroso detectado por AST',
}

# ─── EXTRAER FEATURES CÓDIGO ───
def extraer_features_codigo(ruta):
    ext = Path(ruta).suffix.lower()
    try:
        with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
            codigo = f.read()
    except Exception:
        return None

    n_lineas     = codigo.count('\n')
    n_caracteres = len(codigo)
    entropia     = calcular_entropia(codigo)

    row = {
        'n_lineas':     n_lineas,
        'n_caracteres': n_caracteres,
        'entropia':     entropia,
    }

    todos = set()
    for lista in PATRONES.values():
        for _, nombre in lista:
            todos.add(nombre)
    for _, nombre in PATRON_DEFAULT:
        todos.add(nombre)
    extras = {
        'n_import_sospechoso', 'es_script_disfrazado', 'n_base64_largo',
        'n_vbs_combo_descarga', 'n_vbs_combo_ejecucion',
        'combo_descarga_ejecucion', 'combo_base64_ejecucion',
        'combo_ofuscacion_persistencia', 'ratio_señales_lineas',
        'n_combos', 'entropia_por_linea', 'ratio_señales_chars',
        'n_red_total', 'n_ejecucion_total', 'n_ofuscacion_total',
    }
    for nombre in todos | extras:
        row[nombre] = 0

    for patron, nombre in PATRONES.get(ext, PATRON_DEFAULT):
        row[nombre] = len(re.findall(patron, codigo, re.IGNORECASE))

    if ext == '.py':
        ev, ex, imp = analizar_ast(codigo)
        row['n_eval']              = max(row.get('n_eval', 0), ev)
        row['n_exec']              = max(row.get('n_exec', 0), ex)
        row['n_import_sospechoso'] = imp

    if ext == '.txt':
        primeras = codigo[:500].strip()
        row['es_script_disfrazado'] = int(bool(re.search(
            r'^(#!/|import |function |param\(|<\?php|#!)',
            primeras, re.MULTILINE
        )))
        row['n_base64_largo'] = len(re.findall(r'[A-Za-z0-9+/]{200,}', codigo))
    else:
        row['es_script_disfrazado'] = 0
        row['n_base64_largo']       = 0

    if ext == '.vbs':
        row['n_vbs_combo_descarga'] = int(
            row.get('n_http_vbs', 0) > 0
            and (row.get('n_shell_run', 0) + row.get('n_wscript_shell', 0) +
                 row.get('n_execute', 0)) > 0
        )
        row['n_vbs_combo_ejecucion'] = int(
            (row.get('n_chr', 0) + row.get('n_chrw', 0)) > 5
            and row.get('n_execute', 0) + row.get('n_eval', 0) > 0
        )

    row['combo_descarga_ejecucion'] = int(
        row.get('n_requests', 0) + row.get('n_urllib', 0) +
        row.get('n_webclient', 0) + row.get('n_curl_pipe', 0) +
        row.get('n_wget_curl', 0) + row.get('n_http_vbs', 0) > 0
        and row.get('n_eval', 0) + row.get('n_exec', 0) +
        row.get('n_iex', 0) + row.get('n_execute', 0) +
        row.get('n_shell_run', 0) > 0
    )
    row['combo_base64_ejecucion'] = int(
        row.get('n_base64', 0) + row.get('n_base64_largo', 0) > 0
        and row.get('n_eval', 0) + row.get('n_exec', 0) +
        row.get('n_execute', 0) > 0
    )
    row['combo_ofuscacion_persistencia'] = int(
        row.get('n_base64', 0) + row.get('n_encoded', 0) +
        row.get('n_base64_largo', 0) + row.get('n_chr', 0) > 0
        and row.get('n_registro', 0) + row.get('n_crontab', 0) +
        row.get('n_schtasks', 0) + row.get('n_autorun', 0) > 0
    )

    señales = [
        'n_eval', 'n_exec', 'n_base64', 'n_os_system', 'n_subprocess',
        'n_socket', 'n_requests', 'n_urllib', 'n_ctypes', 'n_winreg',
        'n_marshal', 'n_pickle', 'n_import_dinamico', 'n_iex', 'n_encoded',
        'n_webclient', 'n_bypass', 'n_curl_pipe', 'n_wget_pipe',
        'n_import_sospechoso', 'n_cmd', 'n_wget_curl', 'n_base64_largo',
        'es_script_disfrazado', 'n_createobject', 'n_wscript_shell',
        'n_shell_run', 'n_http_vbs', 'n_execute', 'n_chr', 'n_chrw',
        'n_registro', 'n_autorun', 'n_wmi', 'n_powershell_vbs',
        'n_vbs_combo_descarga', 'n_vbs_combo_ejecucion',
    ]
    total_señales = sum(row.get(s, 0) for s in señales)

    row['ratio_señales_lineas'] = round(total_señales / max(n_lineas, 1), 6)
    row['n_combos'] = (
        row['combo_descarga_ejecucion'] +
        row['combo_base64_ejecucion'] +
        row['combo_ofuscacion_persistencia'] +
        row.get('n_vbs_combo_descarga', 0) +
        row.get('n_vbs_combo_ejecucion', 0)
    )
    row['entropia_por_linea']   = round(entropia / max(n_lineas, 1), 6)
    row['ratio_señales_chars']  = round(total_señales / max(n_caracteres, 1), 8)
    row['n_red_total'] = (
        row.get('n_requests', 0) + row.get('n_urllib', 0) +
        row.get('n_webclient', 0) + row.get('n_curl_pipe', 0) +
        row.get('n_wget_pipe', 0) + row.get('n_wget_curl', 0) +
        row.get('n_urls', 0) + row.get('n_http_vbs', 0)
    )
    row['n_ejecucion_total'] = (
        row.get('n_eval', 0) + row.get('n_exec', 0) +
        row.get('n_iex', 0) + row.get('n_os_system', 0) +
        row.get('n_execute', 0) + row.get('n_shell_run', 0) +
        row.get('n_run', 0)
    )
    row['n_ofuscacion_total'] = (
        row.get('n_base64', 0) + row.get('n_encoded', 0) +
        row.get('n_marshal', 0) + row.get('n_pickle', 0) +
        row.get('n_base64_largo', 0) + row.get('n_chr', 0) +
        row.get('n_chrw', 0)
    )

    return row

# ─── ANALIZAR ARCHIVO ───
def analizar_archivo(ruta):
    ruta = Path(ruta)
    ext  = ruta.suffix.lower()

    resultado = {
        'archivo':   str(ruta),
        'extension': ext,
        'md5':       None,
        'veredicto': 'DESCONOCIDO',
        'score':     0.0,
        'motivo':    '',
        'alertas':   [],
    }

    try:
        md5 = calcular_md5(ruta)
        resultado['md5'] = md5
        if md5 in FIRMAS_CONOCIDAS:
            resultado['veredicto'] = 'MALWARE'
            resultado['score']     = 1.0
            resultado['motivo']    = f"Firma conocida: {FIRMAS_CONOCIDAS[md5]}"
            return resultado
    except Exception as e:
        resultado['alertas'].append(f"Error calculando MD5: {e}")

    if ext in EXTENSIONES_EXE:
        if modelo_exe is None:
            resultado['veredicto'] = 'NO SOPORTADO'
            resultado['motivo']    = "Modelo EXE no disponible"
        else:
            try:
                import pefile
                pe      = pefile.PE(str(ruta))
                imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imports.append(imp.name.decode(errors='ignore'))

                features = pd.DataFrame([{
                    imp: 1 for imp in imports
                }]).reindex(columns=modelo_exe.feature_names_in_, fill_value=0)

                score = modelo_exe.predict_proba(features)[0][1]
                resultado['score'] = round(score, 4)

                if score >= UMBRAL_EXE:
                    resultado['veredicto'] = 'MALWARE'
                    resultado['motivo']    = f"Modelo EXE — score {score:.2f}"
                else:
                    resultado['veredicto'] = 'LIMPIO'
                    resultado['motivo']    = f"Modelo EXE — score {score:.2f}"

            except Exception as e:
                resultado['alertas'].append(f"Error modelo EXE: {e}")

    elif ext in EXTENSIONES_CODIGO:
        if modelo_codigo is None:
            resultado['veredicto'] = 'NO SOPORTADO'
            resultado['motivo']    = "Modelo código no disponible"
        else:
            try:
                features_raw = extraer_features_codigo(ruta)
                if features_raw is None:
                    resultado['motivo'] = "Archivo vacío o ilegible"
                    return resultado

                features = pd.DataFrame([features_raw])\
                             .reindex(columns=features_codigo, fill_value=0)

                score = modelo_codigo.predict_proba(features)[0][1]
                resultado['score'] = round(score, 4)

                for key, desc in ALERTAS_DESCRIPCION.items():
                    if features_raw.get(key, 0) > 0:
                        resultado['alertas'].append(desc)

                if score >= UMBRAL_CODIGO:
                    resultado['veredicto'] = 'MALWARE'
                    resultado['motivo']    = f"Modelo código — score {score:.2f}"
                elif score >= 0.25:
                    resultado['veredicto'] = 'SOSPECHOSO'
                    resultado['motivo']    = f"Modelo código — score {score:.2f}"
                else:
                    resultado['veredicto'] = 'LIMPIO'
                    resultado['motivo']    = f"Modelo código — score {score:.2f}"

            except Exception as e:
                resultado['alertas'].append(f"Error modelo código: {e}")

    else:
        resultado['veredicto'] = 'NO SOPORTADO'
        resultado['motivo']    = f"Extensión {ext} no analizable"

    return resultado

# ─── ESCANEAR CARPETA ───
def escanear_proyecto(carpeta):
    carpeta = Path(carpeta)
    ignorar = {'.git', '__pycache__', '.idea', 'node_modules', '.venv'}
    archivos = []

    for raiz, dirs, ficheros in os.walk(carpeta):
        dirs[:] = [d for d in dirs if d not in ignorar]
        for nombre in ficheros:
            ext = Path(nombre).suffix.lower()
            if ext in EXTENSIONES_EXE | EXTENSIONES_CODIGO:
                archivos.append(Path(raiz) / nombre)

    print(f"\nEscaneando {len(archivos)} archivos en {carpeta}\n")

    resultados = []
    for ruta in archivos:
        r = analizar_archivo(ruta)
        resultados.append(r)

        icono = {
            'MALWARE':      '[ MALWARE    ]',
            'SOSPECHOSO':   '[ SOSPECHOSO ]',
            'LIMPIO':       '[ LIMPIO     ]',
            'NO SOPORTADO': '[ -          ]',
            'DESCONOCIDO':  '[ ?          ]',
        }.get(r['veredicto'], '[ ?          ]')

        print(f"{icono} {r['archivo']}")
        print(f"         Score: {r['score']:.2f} | {r['motivo']}")
        if r['alertas']:
            for alerta in r['alertas']:
                print(f"         ! {alerta}")
        print()

    malware     = [r for r in resultados if r['veredicto'] == 'MALWARE']
    sospechosos = [r for r in resultados if r['veredicto'] == 'SOSPECHOSO']
    limpios     = [r for r in resultados if r['veredicto'] == 'LIMPIO']

    print("=" * 55)
    print(f"  RESUMEN")
    print("=" * 55)
    print(f"  Total analizados : {len(resultados)}")
    print(f"  Malware          : {len(malware)}")
    print(f"  Sospechosos      : {len(sospechosos)}")
    print(f"  Limpios          : {len(limpios)}")
    print("=" * 55)

    return resultados

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso:")
        print("  Analizar archivo:  python analizador.py archivo.vbs")
        print("  Analizar carpeta:  python analizador.py mi_proyecto/")
    else:
        ruta = Path(sys.argv[1])
        if ruta.is_dir():
            escanear_proyecto(ruta)
        elif ruta.is_file():
            r = analizar_archivo(ruta)
            print(f"\nArchivo:   {r['archivo']}")
            print(f"MD5:       {r['md5']}")
            print(f"Veredicto: {r['veredicto']}")
            print(f"Score:     {r['score']:.2f}")
            print(f"Motivo:    {r['motivo']}")
            if r['alertas']:
                print("Alertas:")
                for a in r['alertas']:
                    print(f"  ! {a}")
        else:
            print(f"Error: {ruta} no existe")