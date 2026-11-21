"""
Módulo de Detección Heurística de Cifrado AES
==============================================
Proporciona funciones para analizar archivos y determinar si se encuentran
cifrados mediante AES en modo CBC o si corresponden a medios en texto plano.
"""

import os
from pathlib import Path
from typing import Optional


def es_archivo_aes_encriptado(ruta_archivo: str | Path) -> Optional[bool]:
    """
    Determina heurísticamente si un archivo está cifrado con AES en modo CBC.
    
    Estrategia de detección:
    1. Comprobación de contenido ASCII puro: si el inicio es texto plano ASCII legible,
       no está cifrado con AES.
    2. Inspección de Magic Bytes (Firmas de formato binario conocidas):
       - JPEG: FF D8 FF
       - PNG:  89 50 4E 47 0D 0A 1A 0A
       - MP4:  00 00 00 18 66 74 79 70 (o cualquier box ftyp en offset 4)
    3. Alineación de bloques AES:
       En AES-CBC con padding PKCS#7, la longitud del archivo cifrado debe ser
       estrictamente un múltiplo exacto de 16 bytes (block size).
    
    Retorna:
        True: Si el archivo carece de cabeceras estándar y su tamaño es múltiplo de 16.
        False: Si presenta cabeceras multimedia estándar o tamaño no alineado.
        None: En caso de error de lectura / I/O.
    """
    try:
        ruta = Path(ruta_archivo)
        if not ruta.is_file():
            print(f"[CRYPTO-DETECT] Archivo no encontrado: {ruta}")
            return None

        tamaño_archivo = ruta.stat().st_size
        if tamaño_archivo == 0:
            return False

        with open(ruta, 'rb') as archivo:
            contenido = archivo.read(32)

        # 1. Comprobación de texto ASCII
        if contenido.isascii() and len(contenido) > 0:
            print("[CRYPTO-DETECT] El archivo contiene texto ASCII; no está cifrado.")
            return False

        # 2. Firmas binarias estándar de archivos multimedia no cifrados
        encabezados_comunes = {
            b'\xFF\xD8\xFF': "JPEG/JFIF",
            b'\x89PNG\r\n\x1a\n': "PNG",
            b'\x00\x00\x00\x18ftyp': "MP4 (ftyp box)",
        }
        for firma, formato in encabezados_comunes.items():
            if contenido.startswith(firma):
                print(f"[CRYPTO-DETECT] Encabezado reconocido: formato {formato} sin cifrar.")
                return False

        # Comprobación adicional de contenedor MP4 (ftyp en bytes 4-8)
        if len(contenido) >= 8 and contenido[4:8] == b'ftyp':
            print("[CRYPTO-DETECT] Contenedor MP4 detectado (ftyp box); sin cifrar.")
            return False

        # 3. Comprobación de alineación de bloque (16 bytes para AES)
        if tamaño_archivo % 16 != 0:
            print(f"[CRYPTO-DETECT] Tamaño ({tamaño_archivo} bytes) no es múltiplo de 16; no es AES-CBC.")
            return False

        print("[CRYPTO-DETECT] Archivo identificado como cifrado con AES-CBC.")
        return True

    except Exception as e:
        print(f"[CRYPTO-DETECT] Error al procesar el archivo '{ruta_archivo}': {e}")
        return None
