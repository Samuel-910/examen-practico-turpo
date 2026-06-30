#!/usr/bin/env python3

import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

UMBRAL_ALERTA = 50

PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3}) port"
)

def localizar_log(arg=None):
    """Devuelve la ruta del auth.log probando rutas relativas razonables."""
    if arg:
        return Path(arg)
    for cand in ("lab1/auth.log", "auth.log"):
        if Path(cand).exists():
            return Path(cand)
    return Path("lab1/auth.log")


def analizar(ruta):
    contador = Counter()
    total = 0
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        for linea in f:
            m = PATRON_FALLO.search(linea)
            if m:
                contador[m.group(1)] += 1
                total += 1
    return contador, total


def main():
    ruta = localizar_log(sys.argv[1] if len(sys.argv) > 1 else None)
    if not ruta.exists():
        print(f"[ERROR] No se encuentra el archivo: {ruta}")
        sys.exit(1)

    contador, total = analizar(ruta)
    top10 = contador.most_common(10)

    print("=" * 64)
    print("  ANALISIS FORENSE SSH - Deteccion de fuerza bruta")
    print(f"  Archivo analizado : {ruta}")
    print(f"  Total de intentos fallidos: {total}")
    print("=" * 64)
    print(f"\n  RANKING TOP 10 IPs con mas intentos fallidos\n")
    print(f"  {'#':<4}{'IP de origen':<20}{'Intentos':>10}")
    print(f"  {'-'*4}{'-'*20}{'-'*10}")
    for i, (ip, n) in enumerate(top10, 1):
        print(f"  {i:<4}{ip:<20}{n:>10}")

    print("\n" + "-" * 64)
    ips_sospechosas = []
    hay_alerta = False
    # Recorre TODAS las IPs (no solo el top 10) para alertas
    for ip, n in contador.most_common():
        es_alerta = n > UMBRAL_ALERTA
        if es_alerta:
            hay_alerta = True
            print(f"[ALERTA] IP: {ip} \u2014 {n} intentos fallidos "
                  f"\u2014 Posible ataque de fuerza bruta")
        # Guardamos en el reporte las IPs relevantes (top o con alerta)
        if es_alerta or n >= 10:
            ips_sospechosas.append({"ip": ip, "intentos": n, "alerta": es_alerta})

    if not hay_alerta:
        print("[OK] Ninguna IP supero el umbral de alerta "
              f"({UMBRAL_ALERTA} intentos).")
    print("-" * 64)

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total,
        "ips_sospechosas": ips_sospechosas,
    }

    salida = ruta.parent / "reporte_ssh.json"
    with open(salida, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Reporte exportado a: {salida}")


if __name__ == "__main__":
    main()
