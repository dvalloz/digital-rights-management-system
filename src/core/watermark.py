"""
Módulo de Watermarking Dinámico Forense
=======================================
Inserta marcas de agua visibles personalizadas en imágenes (JPEG, PNG, JFIF)
en tiempo real durante el proceso de streaming, tanto en medios sin cifrar
como en medios cifrados (descifrado en memoria -> inyección de marca -> re-cifrado).
"""

import os
import io
import ast
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw, ImageFont, ImageFile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

ImageFile.LOAD_TRUNCATED_IMAGES = True

# Determinación robusta del directorio de claves y vectores
_CURRENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _CURRENT_DIR.parent
_DEFAULT_KEYS_DIR = _PROJECT_ROOT / "license_server" / "keys"

# Fallback si se ejecuta desde otra ubicación
if not _DEFAULT_KEYS_DIR.exists():
    _CANDIDATE = _PROJECT_ROOT.parent / "Proyecto nuestro" / "Servidor_licencias"
    if _CANDIDATE.exists():
        _DEFAULT_KEYS_DIR = _CANDIDATE

ARCHIVO_CLAVES = _DEFAULT_KEYS_DIR / "claves.txt"
ARCHIVO_VECTORES = _DEFAULT_KEYS_DIR / "vectores.txt"
ARCHIVO_AES_CBC = _DEFAULT_KEYS_DIR / "AES_CBC.txt"


def cargar_archivo(ruta_archivo: Path | str) -> list[str]:
    """Carga las líneas de un archivo de claves de texto plano."""
    p = Path(ruta_archivo)
    if p.is_file():
        with open(p, "r", encoding="utf-8") as f:
            return f.readlines()
    return []


def buscar_clave(posicion: str, lineas: list[str]) -> Optional[bytes]:
    """Busca la clave simétrica de 16 bytes correspondiente a un archivo."""
    for i in range(0, len(lineas), 2):
        if lineas[i].strip().rstrip(':') == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None


def buscar_vector(posicion: str, lineas: list[str]) -> Optional[bytes]:
    """Busca el vector de inicialización IV (16 bytes) para un archivo."""
    for i in range(0, len(lineas), 2):
        if lineas[i].strip().rstrip(':') == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None


def añadir_marcad(archivo: str | Path, usuario: str) -> Optional[bytes]:
    """
    Inserta una marca de agua visible en una imagen sin cifrar (o con cifrado de tránsito).
    
    Args:
        archivo: Ruta al archivo de imagen.
        usuario: Identificador del usuario que solicita la descarga.
        
    Returns:
        Bytes de la imagen procesada con la marca de agua.
    """
    ruta = Path(archivo)
    if not ruta.is_file():
        print(f"[WATERMARK] Archivo no encontrado: {ruta}")
        return None

    ext = ruta.suffix.lower().lstrip('.')
    if ext not in ('jpg', 'png', 'jfif', 'jpeg'):
        print(f"[WATERMARK] Formato no soportado para marca de agua: {ext}")
        return None

    try:
        with open(ruta, 'rb') as f:
            mensaje = f.read()

        # Clave y vector de sesión fijos para procesado simétrico estándar
        clave = b'm\x9cr\x10\x82\x9c^\xa6"\xe3\x9f\xaf\n$e\xe0'
        vector = b'M&\x96\xe4ir\x85\xc9\t4@\x00\x87\x16\xe3\x0e'

        aesCipher_CBC = Cipher(algorithms.AES(clave), modes.CBC(vector))
        aesEncryptor_CBC = aesCipher_CBC.encryptor()
        aesDecryptor_CBC = aesCipher_CBC.decryptor()

        padder = PKCS7(algorithms.AES.block_size).padder()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()

        # Simulación de ciclo seguro en tránsito
        padded_data = padder.update(mensaje) + padder.finalize()
        encrypted_data = aesEncryptor_CBC.update(padded_data) + aesEncryptor_CBC.finalize()
        descifrado_padded = aesDecryptor_CBC.update(encrypted_data) + aesDecryptor_CBC.finalize()
        texto_desencriptado = unpadder.update(descifrado_padded) + unpadder.finalize()

        # Inserción de texto en la imagen con PIL
        img_marca = Image.open(io.BytesIO(texto_desencriptado))
        draw = ImageDraw.Draw(img_marca)
        texto = f"Usuario: {usuario}"

        try:
            fuente = ImageFont.truetype("arial.ttf", 36)
        except Exception:
            fuente = ImageFont.load_default()

        # Marca de agua con sombra para garantizar visibilidad forense
        draw.text((22, 22), texto, font=fuente, fill=(0, 0, 0))
        draw.text((20, 20), texto, font=fuente, fill=(255, 255, 255))

        img_byte_arr = io.BytesIO()
        fmt = img_marca.format or ('JPEG' if ext in ('jpg', 'jpeg', 'jfif') else 'PNG')
        img_marca.save(img_byte_arr, format=fmt)
        resultado = img_byte_arr.getvalue()

        # Persistir copia local en el servidor
        ruta_guardar = ruta.parent / f"marca_{ruta.name}"
        with open(ruta_guardar, 'wb') as f_out:
            f_out.write(resultado)

        return resultado

    except Exception as e:
        print(f"[WATERMARK] Error al añadir marca de agua en claro: {e}")
        return None


def añadir_marcae(archivo: str | Path, usuario: str) -> Optional[bytes]:
    """
    Inserta marca de agua en una imagen CIFRADA con AES-CBC.
    
    Flujo:
    1. Carga clave e IV específicos del archivo desde la base de datos de licencias.
    2. Descifra el archivo en memoria y elimina el padding PKCS#7.
    3. Renderiza la marca de agua personalizada con Pillow.
    4. Aplica nuevo padding PKCS#7 y re-cifra el archivo con su clave AES original.
    5. Retorna los bytes del archivo modificado listo para ser transmitido.
    """
    ruta = Path(archivo)
    if not ruta.is_file():
        print(f"[WATERMARK-ENC] Archivo no encontrado: {ruta}")
        return None

    lineas_claves = cargar_archivo(ARCHIVO_CLAVES)
    lineas_vectores = cargar_archivo(ARCHIVO_VECTORES)

    nombre_archivo = ruta.name
    clave = buscar_clave(nombre_archivo, lineas_claves)
    vector = buscar_vector(nombre_archivo, lineas_vectores)

    if not clave or not vector:
        print(f"[WATERMARK-ENC] Clave o vector no encontrados para '{nombre_archivo}'.")
        return None

    try:
        with open(ruta, 'rb') as f:
            encrypted_data = f.read()

        # 1. Descifrado AES-CBC
        aesCipher_CBC = Cipher(algorithms.AES(clave), modes.CBC(vector))
        decryptor = aesCipher_CBC.decryptor()
        descifrado_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        # 2. Quitar padding PKCS#7
        try:
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            datos_imagen = unpadder.update(descifrado_padded) + unpadder.finalize()
        except Exception:
            datos_imagen = descifrado_padded

        # 3. Aplicar marca de agua sobre la imagen descifrada
        img = Image.open(io.BytesIO(datos_imagen))
        draw = ImageDraw.Draw(img)
        texto = f"Usuario: {usuario}"

        try:
            fuente = ImageFont.truetype("arial.ttf", 36)
        except Exception:
            fuente = ImageFont.load_default()

        # Contorno negro + texto blanco
        draw.text((22, 22), texto, font=fuente, fill=(0, 0, 0))
        draw.text((20, 20), texto, font=fuente, fill=(255, 255, 255))

        img_byte_arr = io.BytesIO()
        fmt = img.format or 'JPEG'
        img.save(img_byte_arr, format=fmt)
        img_bytes = img_byte_arr.getvalue()

        # 4. Re-cifrar con AES-CBC y nuevo padding PKCS#7
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_new = padder.update(img_bytes) + padder.finalize()

        encryptor = aesCipher_CBC.encryptor()
        re_encrypted = encryptor.update(padded_new) + encryptor.finalize()

        # Guardar copia local de control
        ruta_guardar = ruta.parent / f"marca_encriptada_{ruta.name}"
        with open(ruta_guardar, 'wb') as f_out:
            f_out.write(re_encrypted)

        return re_encrypted

    except Exception as e:
        print(f"[WATERMARK-ENC] Error durante el proceso de watermarking cifrado: {e}")
        return None
