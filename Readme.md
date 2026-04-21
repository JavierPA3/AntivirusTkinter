# ⚡ Antivirus ML

Sistema de detección de malware basado en Machine Learning construido desde cero. Combina detección por firma (hash MD5) con dos modelos de Random Forest — uno para ejecutables y otro para código fuente — con interfaz gráfica de escritorio.

---

## 📋 Índice

1. [Descripción del proyecto](#descripción-del-proyecto)
2. [Arquitectura del sistema](#arquitectura-del-sistema)
3. [Requisitos](#requisitos)
4. [Estructura de archivos](#estructura-de-archivos)
5. [Fase 1 — Dataset de ejecutables](#fase-1--dataset-de-ejecutables)
6. [Fase 2 — Dataset de código fuente](#fase-2--dataset-de-código-fuente)
7. [Fase 3 — Entrenamiento de modelos](#fase-3--entrenamiento-de-modelos)
8. [Fase 4 — Motor del antivirus](#fase-4--motor-del-antivirus)
9. [Fase 5 — Interfaz gráfica](#fase-5--interfaz-gráfica)
10. [Resultados obtenidos](#resultados-obtenidos)
11. [Cómo usar](#cómo-usar)
12. [Limitaciones y mejoras futuras](#limitaciones-y-mejoras-futuras)

---

## Descripción del proyecto

Este proyecto implementa un antivirus funcional que analiza archivos en cinco capas:

```
CAPA 1 — Hash MD5        → firma conocida = malware inmediato
CAPA 2 — Señales         → imports, funciones, entropía, strings
CAPA 3 — Correlaciones   → combinaciones peligrosas de señales
CAPA 4 — Contexto        → nombre, ubicación, tamaño del archivo
CAPA 5 — Modelo ML       → Random Forest calibrado → score 0.0 a 1.0
```

El sistema distingue entre dos tipos de archivos:

| Tipo | Extensiones | Modelo |
|------|-------------|--------|
| Ejecutables Windows | `.exe`, `.dll` | Modelo 1 — PE Imports |
| Código fuente | `.py`, `.ps1`, `.js`, `.sh`, `.bat`, `.vbs`, `.txt` | Modelo 2 — Features de código |

---

## Arquitectura del sistema

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
    < 0.4   0.4-0.5   > 0.5
```

---

## Requisitos

### Python 3.10+

```bash
pip install pandas scikit-learn xgboost joblib pefile requests
```

### Librerías utilizadas

| Librería | Uso |
|----------|-----|
| `pandas` | Manipulación del dataset |
| `scikit-learn` | Random Forest, calibración, métricas |
| `joblib` | Guardar y cargar modelos |
| `pefile` | Extraer imports de ejecutables Windows |
| `tkinter` | Interfaz gráfica (incluido en Python) |
| `ast` | Análisis sintáctico de código Python |
| `re` | Detección de patrones regex |

---

## Estructura de archivos

```
Malware/
│
├── 01_descargar_dataset.py        # Descarga el dataset de Kaggle
├── 02_limpiar_dataset.py          # Limpieza y balanceo del dataset EXE
├── 04_extraer_features_codigo.py  # Extractor de features de código fuente
├── 06_entrenar_modelo.py          # Entrenamiento con calibración
├── analizador.py                  # Motor principal del antivirus
├── app.py                         # Interfaz gráfica Tkinter
│
├── modelo.pkl                     # Modelo 1 entrenado (EXE/DLL)
├── modelo_codigo.pkl              # Modelo 2 entrenado (código fuente)
├── features_codigo.pkl            # Nombres de columnas del Modelo 2
│
├── dataset_codigo.csv             # Dataset de código fuente procesado
├── historial.json                 # Historial de análisis por sesión
│
├── Codigos Buenos/                # Scripts limpios para entrenamiento
│   ├── django-main/
│   ├── flask-main/
│   ├── TheAlgorithms-Python/
│   ├── requests/
│   ├── fastapi/
│   └── ...
│
└── Codigos Malos/                 # Scripts maliciosos para entrenamiento
    ├── nishang/
    ├── PayloadsAllTheThings/
    ├── pypi_malregistry/
    └── aggressor-scripts/
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

### Limpieza

```python
import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv('dataset.csv')

# la columna se llama Label con mayúscula
X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
```

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

> ⚠️ Los archivos de `pypi_malregistry` vienen comprimidos en `.tar.gz`. Usar el script de descompresión antes de extraer features.

```python
import tarfile
from pathlib import Path
import os

for raiz, _, archivos in os.walk('Codigos Malos'):
    for nombre in archivos:
        if nombre.endswith(('.tar.gz', '.tgz')):
            ruta = Path(raiz) / nombre
            with tarfile.open(ruta, 'r:*') as tar:
                tar.extractall(path=raiz)
```

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

#### Señales por lenguaje

**Python (`.py`):**

| Feature | Señal detectada |
|---------|-----------------|
| `n_eval` | Llamadas a `eval()` |
| `n_exec` | Llamadas a `exec()` |
| `n_base64` | Uso de codificación base64 |
| `n_subprocess` | Importación de `subprocess` |
| `n_socket` | Uso de sockets de red |
| `n_requests` | Peticiones HTTP con `requests` |
| `n_ctypes` | Llamadas directas a DLLs de Windows |
| `n_winreg` | Modificación del registro de Windows |
| `n_marshal` | Deserialización peligrosa |
| `n_import_sospechoso` | Imports detectados por AST |

**PowerShell (`.ps1`):**

| Feature | Señal detectada |
|---------|-----------------|
| `n_iex` | `Invoke-Expression` / `IEX` |
| `n_encoded` | `-EncodedCommand` / `-enc` |
| `n_webclient` | `WebClient`, `DownloadString` |
| `n_bypass` | Bypass de políticas |
| `n_registro` | Modificación de claves Run |
| `n_mimikatz` | Referencia a Mimikatz |

**Shell / Bash (`.sh`):**

| Feature | Señal detectada |
|---------|-----------------|
| `n_curl_pipe` | `curl ... \| bash` |
| `n_wget_pipe` | `wget ... \| sh` |
| `n_crontab` | Persistencia con cron |
| `n_passwd` | Acceso a `/etc/passwd` |

#### Correlaciones entre señales

| Feature | Combinación detectada | Riesgo |
|---------|----------------------|--------|
| `combo_descarga_ejecucion` | Red + eval/exec/IEX | Alto |
| `combo_base64_ejecucion` | base64 + eval/exec | Alto |
| `combo_ofuscacion_persistencia` | base64 + registro/cron | Muy alto |

#### Features de ratio (nuevas)

| Feature | Fórmula |
|---------|---------|
| `ratio_señales_lineas` | total_señales / n_lineas |
| `entropia_por_linea` | entropia / n_lineas |
| `ratio_señales_chars` | total_señales / n_caracteres |
| `n_red_total` | suma de todas las señales de red |
| `n_ejecucion_total` | suma de todas las señales de ejecución |
| `n_ofuscacion_total` | suma de todas las señales de ofuscación |
| `n_combos` | número de combos activos (0, 1, 2 o 3) |

#### Soporte para `.txt`

Los archivos de texto también se analizan buscando:

- Bloques base64 de más de 200 caracteres sin espacios
- Referencias a `IEX`, `eval`, `powershell`, `cmd.exe`
- URLs (`http://`, `https://`)
- Detección de scripts disfrazados (shebangs, `import`, `function`)

---

## Fase 3 — Entrenamiento de modelos

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

**Resultados (umbral 0.5):**

```
              precision    recall  f1-score
Benigno           0.66      0.81      0.73
Malware           0.99      0.98      0.99
accuracy                              0.98
```

### Modelo 2 — Código fuente

Se usa **calibración isotónica** para estirar las probabilidades hacia los extremos y mejorar la separación entre clases.

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
Limpios  → media: 0.182  (antes ~0.35)
Malware  → media: 0.878  (antes ~0.65)
```

**Resultados (umbral 0.5):**

```
              precision    recall  f1-score   support
Limpio            0.88      0.89      0.89       599
Malware           0.92      0.91      0.91       779
accuracy                              0.90      1378

Limpios  correctos:   536
Falsos positivos:      63
Falsos negativos:      73
Malware correctos:    706
```

### Top 10 features más importantes

```
entropia                ████████████████████  0.186
n_import_sospechoso     ███████████████████   0.179
n_caracteres            █████████████         0.127
n_lineas                █████████████         0.126
n_requests              ████████████          0.111
n_subprocess            ████████              0.074
n_exec                  ████                  0.036
n_urllib                ███                   0.027
n_base64                ███                   0.027
n_ctypes                ██                    0.025
```

> La entropía y los imports sospechosos son los predictores más potentes — los archivos maliciosos tienden a estar más ofuscados y a usar imports de sistema más agresivos.

---

## Fase 4 — Motor del antivirus

El archivo `analizador.py` orquesta las cinco capas de análisis:

```python
UMBRAL_EXE    = 0.5
UMBRAL_CODIGO = 0.5

def analizar_archivo(ruta):
    # Capa 1: hash MD5
    md5 = calcular_md5(ruta)
    if md5 in FIRMAS_CONOCIDAS:
        return veredicto('MALWARE', score=1.0, motivo='Firma conocida')

    # Capa 2-3: señales y correlaciones
    features = extraer_features_codigo(ruta)

    # Capa 4: contexto (extensión, ubicación)

    # Capa 5: modelo ML
    score = modelo.predict_proba(features)[0][1]

    if score >= UMBRAL_CODIGO:
        return veredicto('MALWARE', score)
    elif score >= 0.15:
        return veredicto('SOSPECHOSO', score)
    else:
        return veredicto('LIMPIO', score)
```

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

## Fase 5 — Interfaz gráfica

La aplicación `app.py` es una interfaz Tkinter de escritorio con tema oscuro.

### Cómo ejecutar

```bash
python app.py
```

### Funcionalidades

#### Pestaña Resultados

- Botón **Analizar archivo** — abre un selector de archivo individual
- Botón **Analizar carpeta** — escanea recursivamente una carpeta completa
- Tabla con veredicto, score y señales detectadas por archivo
- **Panel lateral** — al hacer clic en cualquier resultado muestra:
  - Veredicto con color (rojo/naranja/verde)
  - Barra de riesgo visual proporcional al score
  - Explicación en lenguaje humano del veredicto
  - MD5, extensión y motivo del archivo
  - Lista de señales detectadas con `!`
  - Recomendación de acción concreta

#### Pestaña Historial

- Una fila por **sesión de análisis** (no por archivo individual)
- Columnas: fecha, total de archivos, malware, sospechosos, limpios
- Filas en rojo si hubo malware, naranja si solo sospechosos, verde si todo limpio
- **Doble clic** en una sesión abre una ventana con todos los archivos analizados en esa sesión
- Botón para borrar el historial completo

### Colores del sistema

| Veredicto | Color | Significado |
|-----------|-------|-------------|
| MALWARE | 🔴 Rojo | Archivo malicioso confirmado |
| SOSPECHOSO | 🟠 Naranja | Comportamiento inusual, no confirmado |
| LIMPIO | 🟢 Verde | Sin señales detectadas |
| NO SOPORTADO | ⚫ Gris | Extensión no analizable |

---

## Resultados obtenidos

### Resumen de rendimiento

| Métrica | Modelo 1 (EXE) | Modelo 2 (Código) |
|---------|---------------|-------------------|
| Accuracy | 98% | 90% |
| Recall malware | 98% | 91% |
| Precision malware | 99% | 92% |
| Falsos negativos | ~2% | ~9% |
| Falsos positivos | ~34% | ~10% |

> El alto porcentaje de falsos positivos en el Modelo 1 se debe al fuerte desbalanceo del dataset de PE Imports (~3:1). El Modelo 2 está mucho más equilibrado.

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
pip install pandas scikit-learn xgboost joblib pefile requests
```

### 2. Preparar los modelos

Si no tienes los modelos entrenados, ejecuta en orden:

```bash
# Extraer features de código fuente
python 04_extraer_features_codigo.py

# Entrenar el Modelo 2
python 06_entrenar_modelo.py
```

> El Modelo 1 requiere descargar el dataset de PE Imports de Kaggle y ejecutar el script de entrenamiento correspondiente.

### 3. Lanzar la aplicación

```bash
python app.py
```

### 4. Analizar archivos

- Pulsa **Analizar archivo** para seleccionar un fichero concreto
- Pulsa **Analizar carpeta** para escanear un proyecto completo
- Haz clic en cualquier resultado para ver el detalle en el panel lateral
- Ve a la pestaña **Historial** y haz doble clic en una sesión para ver todos sus archivos

---

## Limitaciones y mejoras futuras

### Limitaciones actuales

- El Modelo 1 tiene muchos falsos positivos en archivos benignos — necesita más ejemplos limpios de ejecutables
- El análisis de `.txt` es básico — solo busca patrones superficiales sin contexto sintáctico
- No analiza archivos comprimidos (`.zip`, `.rar`) automáticamente
- No consulta APIs externas como VirusTotal en tiempo real
- Los modelos pueden quedar desactualizados frente a técnicas de evasión nuevas

### Mejoras planificadas

- [ ] Integración con la API de VirusTotal para cruzar hashes
- [ ] Soporte para descomprimir y analizar `.zip` y `.rar`
- [ ] Análisis dinámico básico con sandbox
- [ ] Reentrenamiento automático periódico con nuevas muestras
- [ ] Exportar informe de análisis en PDF
- [ ] Notificaciones del sistema operativo cuando se detecta malware
- [ ] Modo vigilancia — monitorizar una carpeta en tiempo real

---

## Tecnologías

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-orange)
![Tkinter](https://img.shields.io/badge/UI-Tkinter-green)
![Random Forest](https://img.shields.io/badge/Model-Random%20Forest-purple)

---

## Autor

Proyecto desarrollado como ejercicio de aprendizaje en ciberseguridad y machine learning.

---

## Aviso legal

Este proyecto es únicamente para fines educativos e investigación en ciberseguridad. Los datasets de malware utilizados están tomados de repositorios públicos de investigación. No ejecutes ningún archivo de las carpetas de entrenamiento. El autor no se hace responsable del uso indebido de este software.