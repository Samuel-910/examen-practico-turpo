#!/usr/bin/env python3

import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # backend sin pantalla, util en servidores/EC2
import matplotlib.pyplot as plt
import numpy as np

BASE = Path("lab1") if Path("lab1/auth.log").exists() else Path(".")
AUTH = BASE / "auth.log"
ACCESS = BASE / "access.log"
OUT = (BASE / "graficas")
OUT.mkdir(parents=True, exist_ok=True)

PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3}) port"
)
PATRON_WEB = re.compile(
    r'\d{1,3}(?:\.\d{1,3}){3}.*\[(?P<fecha>[^\]]+)\].*"\S+\s+\S+\s+[^"]+"\s+(?P<status>\d{3})'
)
FMT = "%d/%b/%Y:%H:%M:%S %z"


def grafico_top10_ssh():
    contador = Counter()
    with open(AUTH, encoding="utf-8", errors="replace") as f:
        for l in f:
            m = PATRON_FALLO.search(l)
            if m:
                contador[m.group(1)] += 1
    top = contador.most_common(10)
    ips = [t[0] for t in top]
    vals = [t[1] for t in top]

    plt.figure(figsize=(11, 6))
    colores = ["#c0392b" if v > 50 else "#e67e22" if v > 20 else "#3498db"
               for v in vals]
    barras = plt.barh(ips[::-1], vals[::-1], color=colores[::-1])
    plt.title("Top 10 IPs con mas intentos fallidos SSH", fontsize=14, fontweight="bold")
    plt.xlabel("Numero de intentos fallidos")
    plt.ylabel("IP de origen")
    for b, v in zip(barras, vals[::-1]):
        plt.text(v + 0.5, b.get_y() + b.get_height()/2, str(v),
                 va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(OUT / "top10_ssh.png", dpi=120)
    plt.close()
    print("[+] top10_ssh.png")


def _parsear_web():
    horas = []
    por_hora_status = defaultdict(Counter)
    with open(ACCESS, encoding="utf-8", errors="replace") as f:
        for l in f:
            m = PATRON_WEB.search(l)
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("fecha"), FMT)
            except ValueError:
                continue
            h = dt.hour
            horas.append(h)
            por_hora_status[h][int(m.group("status"))] += 1
    return horas, por_hora_status


def grafico_timeline():
    horas, _ = _parsear_web()
    conteo = Counter(horas)
    xs = list(range(24))
    ys = [conteo.get(h, 0) for h in xs]

    plt.figure(figsize=(12, 5))
    plt.plot(xs, ys, marker="o", linewidth=2, color="#2980b9")
    plt.fill_between(xs, ys, alpha=0.15, color="#2980b9")
    plt.title("Peticiones HTTP por hora del dia", fontsize=14, fontweight="bold")
    plt.xlabel("Hora del dia (0-23)")
    plt.ylabel("Numero de peticiones")
    plt.xticks(xs)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / "timeline_http.png", dpi=120)
    plt.close()
    print("[+] timeline_http.png")


def grafico_heatmap():
    _, por_hora_status = _parsear_web()
    codigos = [200, 301, 404, 500]
    matriz = np.zeros((len(codigos), 24), dtype=int)
    for h in range(24):
        for i, c in enumerate(codigos):
            matriz[i, h] = por_hora_status.get(h, Counter()).get(c, 0)

    plt.figure(figsize=(13, 4.5))
    im = plt.imshow(matriz, aspect="auto", cmap="YlOrRd")
    plt.colorbar(im, label="Numero de peticiones")
    plt.yticks(range(len(codigos)), [str(c) for c in codigos])
    plt.xticks(range(24), range(24))
    plt.title("Mapa de calor: peticiones HTTP por hora y codigo de respuesta",
              fontsize=14, fontweight="bold")
    plt.xlabel("Hora del dia")
    plt.ylabel("Codigo HTTP")
    # Anotar valores
    for i in range(len(codigos)):
        for j in range(24):
            if matriz[i, j] > 0:
                plt.text(j, i, matriz[i, j], ha="center", va="center",
                         fontsize=7,
                         color="black" if matriz[i, j] < matriz.max()*0.6 else "white")
    plt.tight_layout()
    plt.savefig(OUT / "heatmap_http.png", dpi=120)
    plt.close()
    print("[+] heatmap_http.png")


if __name__ == "__main__":
    print("Generando graficas en", OUT.resolve())
    grafico_top10_ssh()
    grafico_timeline()
    grafico_heatmap()
    print("Listo. 3 graficas generadas.")
