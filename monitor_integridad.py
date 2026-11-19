import os
import hashlib
import argparse
import json

def calcular_sha256(ruta_archivo):
    h = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        while True:
            bloque = f.read(4096)
            if not bloque:
                break
            h.update(bloque)
    return h.hexdigest()

def escanear_carpeta(carpeta_objetivo):
    estado = {}
    for raiz, _, archivos in os.walk(carpeta_objetivo):
        for nombre in archivos:
            ruta_completa = os.path.join(raiz, nombre)
            estado[ruta_completa] = calcular_sha256(ruta_completa)
    return estado

parser = argparse.ArgumentParser(description="Monitor de Integridad de Archivos (FIM) con SHA-256")
parser.add_argument("-m", "--modo", choices=["init", "check"], required=True, help="Modo: 'init' crea baseline, 'check' audita cambios")
parser.add_argument("-d", "--dir", default="archivos_criticos", help="Carpeta a monitorear")
parser.add_argument("-b", "--baseline", default="baseline.json", help="Archivo JSON de linea base")


args = parser.parse_args()

if not os.path.exists(args.dir):
    print(f"[-] Error: La carpeta '{args.dir}' no existe.")
    exit(1)

if args.modo == "init":
    linea_base = escanear_carpeta(args.dir)
    with open(args.baseline, "w", encoding="utf-8") as f:
        json.dump(linea_base, f, indent=4)
    print(f"[+] Linea base creada en '{args.baseline}' con {len(linea_base)} archivos monitoreados.")

elif args.modo == "check":
    try:
        with open(args.baseline, "r", encoding="utf-8") as f:
            linea_base = json.load(f)
    except FileNotFoundError:
        print(f"[-] No se encontro '{args.baseline}'. Ejecuta primero con: --modo init")
        exit(1)

    estado_actual = escanear_carpeta(args.dir)
    alertas = 0
    archivos_ok = 0
    for ruta, hash_original in linea_base.items():
        if ruta not in estado_actual:
            print(f"[ALERTA - ELIMINADO] El archivo desaparecio: {ruta}")
            alertas += 1
        elif estado_actual[ruta] != hash_original:
            print(f"[ALERTA - MODIFICADO] Integridad comprometida en: {ruta}")
            alertas += 1
        else:
            archivos_ok += 1
    # 2. Buscar archivos nuevos no autorizados
    for ruta in estado_actual:
        if ruta not in linea_base:
            print(f"[ALERTA - NUEVO] Archivo no registrado detectado: {ruta}")
            alertas += 1

    if alertas == 0:
        print("[OK] Integridad verificada: ningun archivo fue alterado.")
    else:
        print(f"[!] Auditoria finalizada con {alertas} alerta(s) de integridad.")

    print(f"[*] Resumen: {archivos_ok} archivo(s) intacto(s), {alertas} alerta(s) detectada(s).")
