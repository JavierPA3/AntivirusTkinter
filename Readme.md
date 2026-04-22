# ⚡ Antivirus ML

Sistema de detección de malware y spam basado en Machine Learning construido desde cero. Combina detección por firma (hash MD5) con tres modelos de Random Forest — ejecutables, código fuente y correos electrónicos — con interfaz gráfica de escritorio, API REST y frontend web.

---

## 📋 Índice

1. [Descripción del proyecto](#descripción-del-proyecto)
2. [Arquitectura del sistema](#arquitectura-del-sistema)
3. [Requisitos](#requisitos)
4. [Estructura de archivos](#estructura-de-archivos)
5. [Fase 1 — Dataset de ejecutables](#fase-1--dataset-de-ejecutables)
6. [Fase 2 — Dataset de código fuente](#fase-2--dataset-de-código-fuente)
7. [Fase 3 — Dataset de correos](#fase-3--dataset-de-correos)
8. [Fase 4 — Entrenamiento de modelos](#fase-4--entrenamiento-de-modelos)
9. [Fase 5 — Motor del antivirus](#fase-5--motor-del-antivirus)
10. [Fase 6 — Interfaz gráfica](#fase-6--interfaz-gráfica)
11. [Fase 7 — API REST Flask](#fase-7--api-rest-flask)
12. [Fase 8 — Frontend React](#fase-8--frontend-react)
13. [Resultados obtenidos](#resultados-obtenidos)
14. [Cómo usar](#cómo-usar)
15. [Limitaciones y mejoras futuras](#limitaciones-y-mejoras-futuras)

---

## Descripción del proyecto

Este proyecto implementa un antivirus funcional que analiza archivos en cinco capas y correos electrónicos de Gmail con detección de spam y phishing:

```
CAPA 1 — Hash MD5        → firma conocida = malware inmediato
CAPA 2 — Señales         → imports, funciones, entropía, strings
CAPA 3 — Correlaciones   → combinaciones peligrosas de señales
CAPA 4 — Contexto        → nombre, ubicación, tamaño del archivo
CAPA 5 — Modelo ML       → Random Forest calibrado → score 0.0 a 1.0
```

El sistema distingue entre tres tipos de análisis:

| Tipo | Extensiones / Fuente | Modelo |
|------|----------------------|--------|
| Ejecutables Windows | `.exe`, `.dll` | Modelo 1 — PE Imports |
| Código fuente | `.py`, `.ps1`, `.js`, `.sh`, `.bat`, `.vbs`, `.txt` | Modelo 2 — Features de código |
| Correos Gmail | IMAP Gmail | Modelo 3 — Features de correo |

---

## Arquitectura del sistema

### Análisis de archivos

```
archivo sospechoso
       │
       ▼
┌─────────────────┐
│   Hash MD5      │ ──► BD firmas conocidas ──► MALWARE (score 1.0)
└─────────────────┘
       │ no coincide
       ▼
┌─────────────────────────────────┐
│  ¿Es ejecutable (.exe/.dll)?    │
└─────────────────────────────────┘
       │                │
      SÍ               NO
       │                │
       ▼                ▼
┌────────────┐  ┌────────────────────┐
│  Modelo 1  │  │     Modelo 2       │
│ PE Imports │  │  Código fuente     │
│ (1000 DLL) │  │  (52 features)     │
└────────────┘  └────────────────────┘
       │                │
       └───────┬────────┘
               ▼
        Score 0.0 – 1.0
               │
       ┌───────┼────────┐
       ▼       ▼        ▼
    LIMPIO  SOSPECH.  MALWARE
    < 0.25  0.25-0.5   > 0.5
```

### Análisis de correos

```
correo entra
       │
       ▼
¿Dominio en lista de 335 empresas verificadas?
       │ SÍ → LEGÍTIMO directo (score 0.02)
       │ NO
       ▼
Extracción de 57 features:
  - Remitente (dominio, SPF, DKIM, reply-to)
  - Asunto (entropía, mayúsculas, urgencia)
  - Contenido (palabras spam ES/EN, patrones phishing)
  - HTML (formularios, iframes, píxeles tracking)
  - Adjuntos (extensiones peligrosas, doble extensión)
       │
       ▼
   Modelo 3 — Random Forest calibrado
       │
       ▼
score < 0.2   → LEGÍTIMO
score 0.2-0.4 → SOSPECHOSO
score > 0.4   → SPAM/PHISHING
```

---

## Requisitos

### Python 3.10+

```bash
pip install pandas scikit-learn joblib pefile requests flask flask-cors beautifulsoup4 tldextract python-dotenv
```

### Node.js 18+ (solo para el frontend)

```bash
npm install
```

### Librerías utilizadas

| Librería | Uso |
|----------|-----|
| `pandas` | Manipulación del dataset |
| `scikit-learn` | Random Forest, calibración, métricas |
| `joblib` | Guardar y cargar modelos |
| `pefile` | Extraer imports de ejecutables Windows |
| `tkinter` | Interfaz gráfica (incluido en Python) |
| `flask` | API REST |
| `flask-cors` | CORS para el frontend |
| `beautifulsoup4` | Parseo de HTML de correos |
| `tldextract` | Extracción de dominios de URLs |
| `ast` | Análisis sintáctico de código Python |
| `re` | Detección de patrones regex |
| `imaplib` | Conexión IMAP con Gmail |

---

## Estructura de archivos

```
Malware/                               ← Proyecto principal (local)
│
├── analizador.py                      # Motor principal del antivirus
├── app.py                             # Interfaz gráfica Tkinter
├── api.py                             # API REST Flask
│
├── correoconnect.py                   # Conexión IMAP Gmail
├── correoextrator.py                  # Extractor de features de correos
├── correofeaturestexto.py             # Features semánticas de texto
├── correo_analizador.py               # Motor de análisis de correos
├── correo_construir_dataset.py        # Constructor del dataset de correos
├── correo_modelo.py                   # Entrenamiento del modelo de correos
├── correo_etiquetar.py                # Etiquetado manual de correos
│
├── 04_extraer_features_codigo.py      # Extractor de features de código fuente
├── 06_entrenar_modelo.py              # Entrenamiento modelo código fuente
│
├── modelo.pkl                         # Modelo 1 entrenado (EXE/DLL)
├── modelo_codigo.pkl                  # Modelo 2 entrenado (código fuente)
├── features_codigo.pkl                # Nombres de columnas del Modelo 2
├── modelo_correos.pkl                 # Modelo 3 entrenado (correos)
├── features_correos.pkl               # Nombres de columnas del Modelo 3
├── empresas_legitimas.csv             # 335 empresas con dominios verificados
│
├── dataset_codigo.csv                 # Dataset de código fuente procesado
├── dataset_correos.csv                # Dataset de correos procesado
├── historial.json                     # Historial de análisis por sesión
│
├── Codigos Buenos/                    # Scripts limpios para entrenamiento
│   ├── django-main/
│   ├── flask-main/
│   ├── TheAlgorithms-Python/
│   └── ...
│
└── Codigos Malos/                     # Scripts maliciosos para entrenamiento
    ├── nishang/
    ├── PayloadsAllTheThings/
    ├── pypi_malregistry/
    └── aggressor-scripts/

antivirus-frontend/                    ← Frontend React
├── src/
│   ├── api/client.js
│   ├── pages/
│   │   ├── Analizador.jsx
│   │   ├── Correos.jsx
│   │   └── Historial.jsx
│   └── components/
│       ├── Header.jsx
│       ├── UploadZone.jsx
│       ├── ResultTable.jsx
│       └── ResultDetail.jsx
└── package.json
```

---

## Fase 1 — Dataset de ejecutables

### Dataset utilizado

**PE Imports Top-1000** de Kaggle (`ang3loliveira/malware-analysis-datasets-top1000-pe-imports`)

Cada fila representa un ejecutable Windows. Las 1000 columnas son las funciones de importación de DLL más comunes, con valores entre 0.0 y 1.0. La columna `Label` indica si es malware (1) o benigno (0).

### Distribución del dataset

```
Total muestras:  ~47.500
Limpios  (0):    ~7.000 – 15.000
Malware  (1):    ~31.000 – 41.000
```

> ⚠️ El dataset tiene un desbalanceo de ~3:1 a favor del malware. Se compensa con `class_weight='balanced'` en el modelo.

---

## Fase 2 — Dataset de código fuente

Como no existe un dataset público directo de scripts maliciosos vs limpios, se construyó uno propio.

### Fuentes de datos

**Scripts maliciosos (label = 1):**

| Repositorio | Contenido | Extensiones |
|-------------|-----------|-------------|
| `samratashok/nishang` | Scripts PowerShell ofensivos | `.ps1` |
| `swisskyrepo/PayloadsAllTheThings` | Payloads de múltiples categorías | `.ps1`, `.sh`, `.py` |
| `rpp0/aggressor-scripts` | Scripts de ataque documentados | `.ps1` |
| `lxyeternal/pypi_malregistry` | ~10.000 paquetes PyPI maliciosos | `.py` |

**Scripts limpios (label = 0):**

| Repositorio | Archivos `.py` aprox. |
|-------------|----------------------|
| `django/django` | ~300 |
| `pallets/flask` | ~150 |
| `TheAlgorithms/Python` | ~500 |
| `psf/requests` | ~150 |
| `tiangolo/fastapi` | ~200 |
| `scrapy/scrapy` | ~300 |
| `celery/celery` | ~250 |
| `sqlalchemy/sqlalchemy` | ~400 |

### Dataset final

```
Total archivos:  6.886
Limpios:         2.994  (43%)
Maliciosos:      3.892  (57%)
Features:        52
```

### Features extraídas por archivo

#### Features base

| Feature | Descripción |
|---------|-------------|
| `n_lineas` | Número de líneas del archivo |
| `n_caracteres` | Longitud total del archivo |
| `entropia` | Entropía de Shannon — valores altos indican ofuscación |

#### Señales por lenguaje (Python, PowerShell, Bash, JS, Batch, VBS, TXT)

Más de 40 patrones regex detectados por extensión incluyendo `eval`, `exec`, `base64`, `subprocess`, `IEX`, `WebClient`, `CreateObject`, `WScript.Shell`, `curl | bash` y muchos más.

#### Correlaciones entre señales

| Feature | Combinación detectada | Riesgo |
|---------|----------------------|--------|
| `combo_descarga_ejecucion` | Red + eval/exec/IEX | Alto |
| `combo_base64_ejecucion` | base64 + eval/exec | Alto |
| `combo_ofuscacion_persistencia` | base64 + registro/cron | Muy alto |

---

## Fase 3 — Dataset de correos

Se combinaron cuatro datasets públicos más un conjunto etiquetado manualmente:

| Dataset | Idioma | Correos | Fuente |
|---------|--------|---------|--------|
| `email_spam.csv` | Español | 1.207 | Kaggle |
| `emails.csv` | Inglés (Enron) | 5.172 | Kaggle |
| `fraud_email_.csv` | Inglés | 11.929 | Kaggle |
| `phishing_email.csv` | Inglés | 18.650 | Kaggle |
| Dataset manual | Español | 100 | Bandeja propia etiquetada |

### Dataset final de correos

```
Total correos:  37.057
Ham (legítimos): 22.421  (60%)
Spam:            14.636  (40%)
Features:            57
```

### Features extraídas por correo

| Categoría | Features |
|-----------|----------|
| Remitente | dominio, nombre vs dominio, guiones, subdominios |
| Asunto | longitud, mayúsculas, exclamaciones, entropía, urgencia |
| URLs | total, dominios únicos, acortadas, externas |
| HTML | longitud, formularios, iframes, scripts, píxel tracking |
| Adjuntos | número, extensiones peligrosas, doble extensión |
| Cabeceras | SPF falla, DKIM falla, DMARC falla, reply-to distinto |
| Contenido | palabras spam ES/EN, patrones phishing, ratio mayúsculas |
| Combos | spam+dinero, urgencia+acción, phishing+URL |

### Lista blanca de empresas

Se creó un CSV con **335 empresas legítimas** y sus dominios oficiales organizadas en 16 categorías (banca, gobierno, ecommerce, telecomunicaciones, tecnología...). Los correos cuyo dominio remitente aparece en esta lista son clasificados directamente como LEGÍTIMO sin pasar por el modelo.

---

## Fase 4 — Entrenamiento de modelos

### Modelo 1 — Ejecutables (PE Imports)

```python
from sklearn.ensemble import RandomForestClassifier

modelo = RandomForestClassifier(
    n_estimators=100,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
```

**Resultados:**

```
Accuracy:         98%
Recall malware:   98%
Precision malware: 99%
```

### Modelo 2 — Código fuente

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

modelo_base = RandomForestClassifier(
    n_estimators=500,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

modelo = CalibratedClassifierCV(modelo_base, method='isotonic', cv=5)
modelo.fit(X_train, y_train)
```

**Distribución de scores tras calibración:**

```
Limpios  → media: 0.182
Malware  → media: 0.878
```

**Resultados (umbral 0.5):**

```
Accuracy:              90%
Recall malware:        91%
Falsos positivos:      63
Falsos negativos:      73
```

### Modelo 3 — Correos

Misma arquitectura que el Modelo 2 con calibración isotónica.

**Resultados (umbral 0.4):**

```
Accuracy:              89%
Recall spam:           87%
Ham media score:       0.130
Spam media score:      0.797
Falsos positivos:      457
Falsos negativos:      385
```

### Top features más importantes (Modelo 3)

```
n_spam_palabras_en    ████████████████████████████████ 0.110
n_palabras            █████████████████████ 0.068
n_caracteres          ███████████████████ 0.064
html_longitud         ██████████████████ 0.062
entropia_texto        ████████████████ 0.056
n_spam_palabras_es    █████████████ 0.047
n_exclamaciones       ████████████ 0.042
ratio_mayusculas      ████████████ 0.041
n_simbolos_dinero     ██████████ 0.032
combo_spam_dinero     ██████████ 0.031
```

---

## Fase 5 — Motor del antivirus

El archivo `analizador.py` orquesta las cinco capas de análisis de archivos y `correo_analizador.py` gestiona el análisis de correos con whitelist + modelo ML.

### Uso desde línea de comandos

```bash
# Analizar un archivo concreto
python analizador.py archivo.py

# Analizar una carpeta entera
python analizador.py mi_proyecto/
```

### Salida de ejemplo

```
[ MALWARE    ] loader.py
         Score: 0.91 | Modelo código — score 0.91
         ! eval() detectado
         ! base64 detectado
         ! COMBO: descarga + ejecucion

[ LIMPIO     ] utils.py
         Score: 0.04 | Modelo código — score 0.04

[ SOSPECHOSO ] helpers.py
         Score: 0.43 | Modelo código — score 0.43
         ! subprocess detectado
```

---

## Fase 6 — Interfaz gráfica

La aplicación `app.py` es una interfaz Tkinter de escritorio con tema oscuro Catppuccin.

### Cómo ejecutar

```bash
python app.py
```

### Funcionalidades

#### Pestaña Archivos

- Botón **Analizar archivo** — selecciona un archivo individual
- Botón **Analizar carpeta** — escanea recursivamente una carpeta completa
- Tabla con veredicto, score y señales detectadas por archivo
- **Panel lateral** — detalle completo al hacer clic en un resultado

#### Pestaña Correos

- **Login seguro** — introduce email y contraseña de aplicación de Gmail (16 caracteres)
- **Enlace directo** a `myaccount.google.com/apppasswords` para generarla
- **Carga automática** de los últimos 10 correos al conectarse
- Spinner para seleccionar cuántos correos analizar
- Checkbox para analizar solo no leídos
- **Doble clic** en un correo para leer el contenido completo

#### Pestaña Historial

- Una fila por sesión de análisis
- Doble clic en una sesión para ver todos sus archivos
- Botón para borrar el historial completo

### Colores del sistema

| Veredicto | Color | Significado |
|-----------|-------|-------------|
| MALWARE / SPAM/PHISHING | 🔴 Rojo | Archivo/correo malicioso |
| SOSPECHOSO | 🟠 Naranja | Comportamiento inusual |
| LIMPIO / LEGÍTIMO | 🟢 Verde | Sin señales detectadas |
| NO SOPORTADO | ⚫ Gris | Extensión no analizable |

---

## Fase 7 — API REST Flask

### Arrancar la API

```bash
python api.py
```

### Endpoints

#### Archivos

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/health` | Estado de la API y modelos |
| POST | `/api/analizar/archivo` | Analizar un archivo |
| POST | `/api/analizar/carpeta` | Analizar carpeta en ZIP |
| GET | `/api/historial` | Lista de sesiones |
| GET | `/api/historial/<id>` | Detalle de sesión |
| DELETE | `/api/historial` | Borrar todo el historial |
| DELETE | `/api/historial/<id>` | Borrar sesión |

#### Correos

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/correos/login` | Conectar Gmail (devuelve token) |
| POST | `/api/correos/logout` | Desconectar |
| GET | `/api/correos/estado` | Estado de conexión |
| POST | `/api/correos/escanear` | Escanear bandeja de entrada |
| GET | `/api/correos/leer/<uid>` | Leer correo completo |

### Autenticación de correos

El módulo de correos usa un sistema de **tokens de sesión en memoria**. El usuario introduce sus credenciales una vez, se verifica la conexión IMAP y se devuelve un token UUID. Las peticiones posteriores llevan el token en el header `X-Correo-Token`.

```bash
# login
curl -X POST http://localhost:5000/api/correos/login \
  -H "Content-Type: application/json" \
  -d '{"email": "tu@gmail.com", "password": "xxxx xxxx xxxx xxxx"}'

# escanear bandeja
curl -X POST http://localhost:5000/api/correos/escanear \
  -H "Content-Type: application/json" \
  -H "X-Correo-Token: tu-token" \
  -d '{"limite": 10, "solo_no_leidos": false}'
```

---

## Fase 8 — Frontend React

Interfaz web con tema oscuro Catppuccin, CSS puro sin Tailwind.

### Arrancar el frontend

```bash
cd antivirus-frontend
npm install
npm run dev
```

Abre `http://localhost:5173` en el navegador.

### Configurar URL de la API

Edita `src/api/client.js`:

```js
const BASE_URL = 'http://localhost:5000/api'
```

---

## Resultados obtenidos

### Resumen de rendimiento

| Métrica | Modelo 1 (EXE) | Modelo 2 (Código) | Modelo 3 (Correos) |
|---------|---------------|-------------------|-------------------|
| Accuracy | 98% | 90% | 89% |
| Recall malware/spam | 98% | 91% | 87% |
| Precision malware/spam | 99% | 92% | 85% |
| Dataset | ~47.500 | ~6.900 | ~37.000 |
| Features | 1.000 | 52 | 57 |
| Umbral | 0.5 | 0.5 | 0.4 |

### Evolución del Modelo 2

| Versión | Dataset | Umbral | FP | FN | Accuracy |
|---------|---------|--------|----|----|----------|
| v1 | 1.102 archivos | 0.3 | 20 | 129 | 86% |
| v2 | 5.467 archivos | 0.4 | 49 | 85 | 90% |
| v3 + calibración | 6.886 archivos | 0.5 | 63 | 73 | 90% |

---

## Cómo usar

### 1. Instalar dependencias

```bash
pip install pandas scikit-learn joblib pefile flask flask-cors beautifulsoup4 tldextract python-dotenv
```

### 2. Lanzar la aplicación de escritorio

```bash
python app.py
```

### 3. Lanzar la API

```bash
python api.py
```

### 4. Lanzar el frontend (requiere Node.js)

```bash
cd antivirus-frontend
npm install
npm run dev
```

### 5. Configurar Gmail

```
1. Ve a myaccount.google.com
2. Seguridad → Verificación en dos pasos (actívala)
3. Ve a https://myaccount.google.com/apppasswords
4. Genera una contraseña de 16 caracteres
5. Úsala en la pestaña Correos de la app
```

---

## Limitaciones y mejoras futuras

### Limitaciones actuales

- El Modelo 1 tiene falsos positivos en archivos benignos por el desbalanceo del dataset
- No analiza archivos comprimidos automáticamente
- No consulta APIs externas como VirusTotal en tiempo real
- Los modelos pueden quedar desactualizados frente a técnicas de evasión nuevas
- El módulo de correos solo funciona con Gmail (no Outlook, Yahoo, etc.)

### Mejoras planificadas

- [ ] Integración con la API de VirusTotal
- [ ] Soporte para descomprimir y analizar `.zip` y `.rar`
- [ ] Soporte para Outlook y otros proveedores de correo
- [ ] Análisis de macros en documentos Office (.vba)
- [ ] Exportar informe de análisis en PDF
- [ ] Modo vigilancia — monitorizar una carpeta en tiempo real
- [ ] Reentrenamiento automático con nuevas muestras etiquetadas

---

## Tecnologías

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-orange)
![Flask](https://img.shields.io/badge/API-Flask-lightgrey)
![React](https://img.shields.io/badge/Frontend-React-61dafb)
![Tkinter](https://img.shields.io/badge/UI-Tkinter-green)
![Random Forest](https://img.shields.io/badge/Model-Random%20Forest-purple)

---

## Autor

**Javier Postigo Arévalo**

- GitHub: [github.com/JavierPA3](https://github.com/JavierPA3)
- LinkedIn: [linkedin.com/in/javierpostigoarevalo](https://www.linkedin.com/in/javierpostigoarevalo/)
- Portfolio: [javierpa3.github.io/PersonalPorfolio](https://javierpa3.github.io/PersonalPorfolio/)

---

## Aviso legal

Este proyecto es únicamente para fines educativos e investigación en ciberseguridad. Los datasets de malware utilizados están tomados de repositorios públicos de investigación. No ejecutes ningún archivo de las carpetas de entrenamiento. El autor no se hace responsable del uso indebido de este software.
