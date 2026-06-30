#!/usr/bin/env python3

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

UMBRAL_RUTAS = 20       # rutas distintas
VENTANA_SEG = 60        # segundos
SQLI_PATTERNS = ["UNION", "SELECT", "--", "OR 1=1", "'"]

# Combined Log Format:
# IP - - [10/Oct/2000:13:55:36 -0700] "GET /url HTTP/1.0" 200 2326 "ref" "ua"
# Capturamos la peticion COMPLETA entre comillas para no truncar URLs que
# contengan espacios (ej. payloads SQLi con 'UNION SELECT ...').
PATRON_LOG = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<fecha>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
FMT_FECHA = "%d/%b/%Y:%H:%M:%S %z"


def _separar_request(request):
    """Divide 'GET /url con espacios HTTP/1.1' en (metodo, url, proto)."""
    partes = request.split(" ")
    if not partes:
        return "", "", ""
    metodo = partes[0]
    if len(partes) >= 3 and partes[-1].upper().startswith("HTTP/"):
        proto = partes[-1]
        url = " ".join(partes[1:-1])
    else:
        proto = ""
        url = " ".join(partes[1:])
    return metodo, url, proto


def localizar_log(arg=None):
    if arg:
        return Path(arg)
    for cand in ("lab1/access.log", "access.log"):
        if Path(cand).exists():
            return Path(cand)
    return Path("lab1/access.log")


def parsear(ruta):
    """Devuelve lista de dicts con los campos parseados."""
    registros = []
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        for linea in f:
            m = PATRON_LOG.search(linea)
            if not m:
                continue
            d = m.groupdict()
            metodo, url, proto = _separar_request(d["request"])
            d["metodo"], d["url"], d["proto"] = metodo, url, proto
            try:
                d["dt"] = datetime.strptime(d["fecha"], FMT_FECHA)
            except ValueError:
                d["dt"] = None
            d["status"] = int(d["status"])
            registros.append(d)
    return registros


def detectar_escaneo(registros):
    """Ventana deslizante por IP: >UMBRAL rutas distintas en <VENTANA segundos."""
    por_ip = defaultdict(list)
    for r in registros:
        if r["dt"]:
            por_ip[r["ip"]].append((r["dt"], r["url"]))

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda x: x[0])
        n = len(eventos)
        i = 0
        ya_alertada = False
        for j in range(n):
            # Mover el inicio de la ventana
            while eventos[j][0] - eventos[i][0] > _timedelta(VENTANA_SEG):
                i += 1
            rutas_distintas = {eventos[k][1] for k in range(i, j + 1)}
            if len(rutas_distintas) > UMBRAL_RUTAS and not ya_alertada:
                hallazgos.append({
                    "ip": ip,
                    "rutas_distintas": len(rutas_distintas),
                    "ventana_seg": VENTANA_SEG,
                    "ejemplo_rutas": sorted(rutas_distintas)[:10],
                })
                ya_alertada = True
                break
    return hallazgos


def _timedelta(segundos):
    from datetime import timedelta
    return timedelta(seconds=segundos)


def agrupar_errores(registros):
    """Codigos 4xx y 5xx agrupados por IP."""
    err = defaultdict(lambda: {"4xx": 0, "5xx": 0, "detalle": defaultdict(int)})
    for r in registros:
        s = r["status"]
        if 400 <= s < 500:
            err[r["ip"]]["4xx"] += 1
            err[r["ip"]]["detalle"][s] += 1
        elif 500 <= s < 600:
            err[r["ip"]]["5xx"] += 1
            err[r["ip"]]["detalle"][s] += 1
    salida = []
    for ip, v in err.items():
        salida.append({
            "ip": ip,
            "errores_4xx": v["4xx"],
            "errores_5xx": v["5xx"],
            "por_codigo": dict(v["detalle"]),
        })
    salida.sort(key=lambda x: x["errores_4xx"] + x["errores_5xx"], reverse=True)
    return salida


def detectar_sqli(registros):
    hallazgos = []
    for r in registros:
        url_upper = r["url"].upper()
        coincidencias = [p for p in SQLI_PATTERNS
                         if (p.upper() in url_upper if p not in ("'", "--")
                             else p in r["url"])]
        if coincidencias:
            hallazgos.append({
                "ip": r["ip"],
                "url": r["url"],
                "status": r["status"],
                "patrones": coincidencias,
            })
    return hallazgos


def main():
    ruta = localizar_log(sys.argv[1] if len(sys.argv) > 1 else None)
    if not ruta.exists():
        print(f"[ERROR] No se encuentra el archivo: {ruta}")
        sys.exit(1)

    registros = parsear(ruta)
    print("=" * 64)
    print("  ANALISIS DE ACCESS.LOG (Apache Combined Log Format)")
    print(f"  Archivo: {ruta}")
    print(f"  Lineas parseadas: {len(registros)}")
    print("=" * 64)

    escaneo = detectar_escaneo(registros)
    print(f"\n[1] ESCANEO DE DIRECTORIOS "
          f"(> {UMBRAL_RUTAS} rutas distintas en < {VENTANA_SEG}s)")
    if escaneo:
        for h in escaneo:
            print(f"  [ALERTA] IP: {h['ip']} \u2014 {h['rutas_distintas']} "
                  f"rutas distintas en {h['ventana_seg']}s \u2014 Posible escaneo")
    else:
        print("  Sin escaneos detectados.")

    sqli = detectar_sqli(registros)
    print(f"\n[2] POSIBLES SQL INJECTION (patrones {SQLI_PATTERNS})")
    if sqli:
        for h in sqli[:15]:
            print(f"  [ALERTA] IP: {h['ip']} \u2014 patrones {h['patrones']} "
                  f"\u2014 {h['url'][:70]}")
        if len(sqli) > 15:
            print(f"  ... y {len(sqli)-15} mas.")
    else:
        print("  Sin intentos de SQLi detectados.")

    errores = agrupar_errores(registros)
    print(f"\n[3] ERRORES 4xx/5xx por IP (Top 10)")
    for e in errores[:10]:
        print(f"  {e['ip']:<18} 4xx={e['errores_4xx']:<4} "
              f"5xx={e['errores_5xx']:<4} {e['por_codigo']}")

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "lineas_parseadas": len(registros),
        "escaneo_directorios": escaneo,
        "sql_injection": sqli,
        "errores_por_ip": errores,
    }
    salida = ruta.parent / "reporte_web.json"
    with open(salida, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Reporte exportado a: {salida}")


if __name__ == "__main__":
    main()
