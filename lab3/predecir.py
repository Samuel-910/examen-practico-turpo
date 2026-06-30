import sys
import pandas as pd
import joblib
from pathlib import Path

def principal():
    if len(sys.argv) < 2:
        print("Uso: python predecir.py <nuevo_trafico.csv>")
        sys.exit(1)

    archivo_csv = sys.argv[1]
    
    if not Path(archivo_csv).exists():
        print(f"[ERROR] No se encuentra el archivo: {archivo_csv}")
        sys.exit(1)

    print("[*] Cargando 'modelo_anomalias.pkl'...")
    try:
        data = joblib.load('modelo_anomalias.pkl')
        modelo = data['modelo']
        scaler = data['scaler']
        features = data['features']
    except Exception as e:
        print(f"[ERROR] No se pudo cargar el modelo: {e}")
        sys.exit(1)

    print(f"[*] Cargando nuevos datos desde {archivo_csv}...")
    df = pd.read_csv(archivo_csv)

    # 1. Replicar el Feature Engineering necesario para el nuevo CSV
    if 'ratio_bytes' not in df.columns:
        df['ratio_bytes'] = df['bytes_recv'] / (df['bytes_sent'] + 1)
    if 'bytes_por_segundo' not in df.columns:
        df['bytes_por_segundo'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 1)

    faltantes = [f for f in features if f not in df.columns]
    if faltantes:
        print(f"[ERROR] Faltan las siguientes columnas en el CSV: {faltantes}")
        sys.exit(1)

    # 2. Normalizar usando el scaler original que guardamos
    X_nuevo = df[features].copy()
    X_nuevo[features] = scaler.transform(X_nuevo[features])

    # 3. Realizar predicciones y obtener scores
    predicciones = modelo.predict(X_nuevo)
    scores = modelo.decision_function(X_nuevo)

    df['prediccion'] = predicciones
    df['score_anomalia'] = scores

    # 4. Aislar las anomalías (-1)
    anomalias = df[df['prediccion'] == -1].sort_values(by='score_anomalia')

    print("=" * 60)
    print(f"  RESULTADOS DE LA PREDICCIÓN")
    print("=" * 60)
    
    if anomalias.empty:
        print("  No se detectaron anomalías en el tráfico analizado.")
    else:
        print(f"  [ALERTA] Se detectaron {len(anomalias)} registros anómalos.\n")
        print(f"  {'IP Origen':<16} | {'IP Destino':<16} | {'Score'}")
        print("-" * 60)
        for idx, row in anomalias.iterrows():
            print(f"  {row['src_ip']:<16} | {row['dst_ip']:<16} | {row['score_anomalia']:.3f}")

if __name__ == "__main__":
    principal()