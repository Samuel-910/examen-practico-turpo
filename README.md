# Examen Práctico Final — Seguridad Informática (Unidad IV)

**Curso:** Seguridad Informática — Unidad IV: Monitoreo de Seguridad, SIEM e Inteligencia Artificial
**Escuela:** Ingeniería de Sistemas — Ciclo IX
**Autor:** _Jose Turpo_
**Repositorio:** `examen-practico-turpo`

> **IMPORTANTE — antes de entregar:**
> 1. Renombra la carpeta del repo a `examen-practico-<tuapellido>` (minúsculas).
> 2. Reemplaza `<Tu Nombre y Apellido>` en este README, en el notebook y en el panel de Grafana.
> 3. Sustituye los datos de prueba sintéticos por los archivos oficiales del curso
>    (`examenfinal/lab1/auth.log`, `access.log`, `examenfinal/lab3/network_traffic.csv`).
> 4. Ejecuta cada laboratorio **en tu entorno** y toma los screenshots requeridos
>    (con tu nombre y fecha/hora visibles). Esos screenshots son responsabilidad tuya.

---

## 1. Entorno de trabajo

| Componente | Versión usada | Comprobación |
|---|---|---|
| Sistema operativo | Ubuntu 22.04 LTS | `lsb_release -a` |
| Python | 3.11+ | `python3 --version` |
| Wazuh Manager | 4.x | `/var/ossec/bin/wazuh-control info` |
| Elastic Stack | 8.x | `curl -k https://localhost:9200` |
| Grafana | 10.x | `grafana-server -v` |
| Jupyter | Notebook/Lab | `jupyter --version` |

> Rellena la columna "Versión usada" con las versiones reales de tu máquina y
> añade capturas de los servicios activos.

### 1.1 Instalación de dependencias Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt`:

```
pandas
numpy
scikit-learn
matplotlib
seaborn
joblib
jupyterlab
nbformat
```

### 1.2 (Opcional) Modalidad AWS Education

Si tu equipo no cumple el mínimo recomendado (8 GB RAM, 4 vCPU, 50 GB),
documenta aquí: especificaciones de tu equipo personal, ID de instancia(s) EC2,
región (`us-east-1`), AMI usada y los comandos de instalación. Los screenshots
deben mostrar el prompt con el hostname EC2 (ej. `ubuntu@ip-10-0-1-5`) o la URL
del servicio AWS.

---

## 2. Reproducción de cada laboratorio

Todos los scripts se ejecutan **desde la raíz del repositorio** salvo que se indique.

### Lab 1 — Análisis Forense de Logs (Python)

```bash
# 1.1 Análisis SSH (genera reporte_ssh.json + alertas en consola)
python lab1/analizar_ssh.py

# 1.2 Análisis web (escaneo, SQLi, errores -> reporte_web.json)
python lab1/analizar_web.py

# 1.3 Visualizaciones (genera 3 PNG en lab1/graficas/)
python lab1/visualizar.py
```

- `analizar_ssh.py`: cuenta `Failed password` por IP, ranking Top 10 y alerta
  `[ALERTA]` para IPs con más de 50 intentos.
- `analizar_web.py`: parsea Combined Log Format, detecta escaneo de directorios
  (>20 rutas distintas en <60 s), agrupa 4xx/5xx por IP y detecta SQLi
  (`UNION`, `SELECT`, `--`, `OR 1=1`, `'`).
- `visualizar.py`: barras Top 10 SSH, línea de peticiones por hora y heatmap
  hora × código HTTP.

### Lab 2 — Reglas de Correlación Wazuh

```bash
# Copiar las reglas al directorio de Wazuh
sudo cp lab2/local_rules_ssh.xml   /var/ossec/etc/rules/
sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/

# Validar sintaxis XML
xmllint --noout lab2/local_rules_ssh.xml   && echo OK
xmllint --noout lab2/local_rules_exfil.xml && echo OK

# Reiniciar el manager y simular el ataque
sudo systemctl restart wazuh-manager
chmod +x lab2/simular_bruteforce.sh
./lab2/simular_bruteforce.sh 127.0.0.1 usuario_inexistente

# Revisar la alerta disparada
sudo tail -n 50 /var/ossec/logs/alerts/alerts.log | grep -A6 100001
```

- `local_rules_ssh.xml` (rule 100001): 10 fallos SSH en 60 s desde la misma IP,
  nivel 10, grupos `authentication_failures,brute_force`.
- `local_rules_exfil.xml` (rules 100010-100012): correlación de transferencia
  saliente >500 MB tras un login fuera de horario (22:00–06:00), nivel 14.

### Lab 3 — Detección de Anomalías (ML)

```bash
# Abrir el notebook (desde la raíz del repo)
jupyter notebook lab3/deteccion_anomalias.ipynb
# Ejecutar todas las celdas: EDA -> Isolation Forest -> métricas -> umbral -> export

# Predicción sobre un CSV nuevo
python lab3/predecir.py lab3/nuevo_trafico.csv
```

- Modelo: **Isolation Forest** (`contamination=0.05`, `n_estimators=100`,
  `random_state=42`), entrenado **sin** la columna `label`.
- Métricas obtenidas con los datos de prueba: **Precision ≈ 0.87, Recall ≈ 0.88,
  F1 ≈ 0.87** (umbral por defecto); F1 ≈ 0.92 con el umbral óptimo.
- `predecir.py` carga `modelo_anomalias.pkl` (modelo + scaler + features) y
  clasifica un CSV nuevo, imprimiendo las anomalías con su score.

### Lab 4 — Dashboard SOC (Grafana)

```bash
# 1. Crear el datasource Elasticsearch (ver lab4/datasource_config.json)
# 2. En Grafana: Dashboards -> Import -> subir lab4/dashboard_soc.json
# 3. Seleccionar el datasource "Elasticsearch (Wazuh)" cuando lo solicite
```

- Dashboard **"SOC - Monitor de Seguridad"** con 4 visualizaciones:
  V1 barras por `rule.level`, V2 tabla Top 10 `data.srcip`, V3 línea de alertas
  por hora, V4 pie por `rule.groups`, más panel de texto del autor.
- Rango de tiempo global: últimas 24 h. Alerta de umbral en V3: >5 eventos
  nivel ≥10 en 5 min (configúrala y captura `SCR-4.4`).

---

## 3. Estructura del repositorio

```
examen-practico-<apellido>/
├── README.md
├── requirements.txt
├── lab1/  (analizar_ssh.py, analizar_web.py, visualizar.py, reportes, graficas/, evidencias/)
├── lab2/  (local_rules_ssh.xml, local_rules_exfil.xml, simular_bruteforce.sh, evidencias/)
├── lab3/  (deteccion_anomalias.ipynb, predecir.py, modelo_anomalias.pkl, network_traffic.csv, evidencias/)
├── lab4/  (dashboard_soc.json, datasource_config.json, evidencias/)
└── utilidades/  (scripts que GENERARON los datos de prueba sintéticos; opcional)
```

> La carpeta `utilidades/` contiene los generadores de los datos de prueba
> (`_generar_datos_logs.py`, `_generar_dataset.py`, `_construir_notebook.py`).
> No son parte de los entregables exigidos; sirven para regenerar datos de
> desarrollo. Elimínala si quieres entregar solo lo pedido.

---

## 4. Flujo Git inicial

```bash
git init
git add .
git commit -m "Estructura inicial del examen práctico"
git remote add origin <URL_de_tu_repo>
git branch -M main
git push -u origin main
# ... commits frecuentes por cada laboratorio terminado ...
```
