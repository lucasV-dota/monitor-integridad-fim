# Monitor de Integridad de Archivos - FIM (monitor_integridad.py)

Herramienta defensiva (Blue Team) desarrollada en Python para monitorear la integridad de directorios y archivos de configuración críticos mediante firmas criptográficas **SHA-256** (`hashlib`).

## Características

- **Generación de Línea Base (`-m init`):** Escanea recursivamente el directorio objetivo con `os.walk`, calcula el hash SHA-256 en lectura binaria por bloques de 4096 bytes y almacena la referencia en `baseline.json`.
- **Auditoría de Integridad (`-m check`):** Compara el estado actual del sistema de archivos contra la línea base para detectar y alertar sobre:
  - Archivos **modificados** (alteración de contenido / hash distinto).
  - Archivos **eliminados** (borrado no autorizado).
  - Archivos **nuevos** (posibles backdoors o scripts maliciosos añadidos).

## Uso

- Crear o actualizar la línea base inicial: `python3 monitor_integridad.py -m init -d archivos_criticos`
- Auditar integridad contra la línea base: `python3 monitor_integridad.py -m check -d archivos_criticos`
