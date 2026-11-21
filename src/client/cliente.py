"""
Cliente Integrado DRM (Fases I y II)
=====================================
Aplicación cliente que interactúa con el Servidor de Contenidos (puerto 8000)
y el Servidor de Licencias (puerto 9000).

Capacidades:
- Autenticación con identificador de usuario para rastreo forense (watermark).
- Consulta de catálogo por formato multimedia o listado global.
- Descarga de ficheros con control de flujo TCP.
- Detección heurística automática de cifrado AES.
- Negociación de canal seguro asimétrico (RSA-2048) / simétrico (AES-128-CBC).
- Emisión de solicitudes de licencia firmadas digitalmente con RSA-PSS.
- Descifrado simétrico AES-128-CBC local con descarte de padding PKCS#7.
"""

import os
import sys
import time
import threading
from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, gethostname

# Asegurar importación de src/core
SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.crypto_detect import es_archivo_aes_encriptado
from core.digital_signature import generar_claves, firma_digital
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7

DOWNLOADS_DIR = Path(__file__).resolve().parent / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Par de claves RSA local del cliente
CLAVE_PRIVADA, CLAVE_PUBLICA_PEM = generar_claves()


def des_asi(mensaje_encriptado: bytes, clave_privada) -> bytes:
    """Descifra un criptograma asimétrico con la clave privada local usando OAEP (SHA-256)."""
    return clave_privada.decrypt(
        mensaje_encriptado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def desencriptar_archivo(nombre_fichero: str, license_host: str = '', license_port: int = 9000) -> None:
    """
    Solicita la licencia al Servidor de Licencias por un canal seguro y descifra el archivo local.
    """
    ruta_archivo = DOWNLOADS_DIR / nombre_fichero
    if not ruta_archivo.is_file():
        print(f"[CLIENT-DRM] Archivo descargado no encontrado: {ruta_archivo}")
        return

    host = license_host or gethostbyname(gethostname())
    print(f"[CLIENT-DRM] Conectando al Servidor de Licencias en ({host}, {license_port})...")

    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((host, license_port))

        # 1. Enviar clave pública PEM para establecer el canal seguro
        sock.send(CLAVE_PUBLICA_PEM)
        time.sleep(0.5)
        confirmacion = sock.recv(2048).decode('utf-8', errors='ignore')

        if 'READY' in confirmacion:
            empieza = sock.recv(2048).decode('utf-8', errors='ignore')
            if 'GO' in empieza:
                # 2. Obtener clave y vector de sesión simétricos cifrados con RSA
                sock.send(b'KEY_SIM')
                key_sim_cif = sock.recv(2048)
                key_sim = des_asi(key_sim_cif, CLAVE_PRIVADA)

                sock.send(b'VEC_SIM')
                vec_sim_cif = sock.recv(2048)
                vec_sim = des_asi(vec_sim_cif, CLAVE_PRIVADA)

                print("[CLIENT-DRM] Canal seguro de sesión establecido exitosamente.")

                # Preparar descifrador para la comunicación
                aes_comu = Cipher(algorithms.AES(key_sim), modes.CBC(vec_sim))
                decryptor_comu = aes_comu.decryptor()

                # 3. Firma digital RSA-PSS de la solicitud
                solicitud = f"GET {nombre_fichero}"
                firma = firma_digital(solicitud, CLAVE_PRIVADA)
                mensaje_firmado = solicitud.encode('utf-8') + b' ...' + firma + b'...' + CLAVE_PUBLICA_PEM
                sock.send(mensaje_firmado)
                print(f"[CLIENT-DRM] Petición de licencia firmada digitalmente enviada.")

                # 4. Recepción de la clave de contenido cifrada
                key_cif = sock.recv(2048)
                key_contenido = decryptor_comu.update(key_cif) + decryptor_comu.finalize()

                if len(key_contenido) != 16:
                    print(f"[CLIENT-DRM] Longitud de clave de contenido inválida ({len(key_contenido)} bytes).")
                    sock.close()
                    return

                # 5. Solicitar vector de contenido (IV)
                aes_comu2 = Cipher(algorithms.AES(key_sim), modes.CBC(vec_sim))
                decryptor_comu2 = aes_comu2.decryptor()
                sock.send(f"OK {nombre_fichero}".encode('utf-8'))
                v_cif = sock.recv(2048)
                vec_contenido = decryptor_comu2.update(v_cif) + decryptor_comu2.finalize()

                print("[CLIENT-DRM] Clave e IV de contenido obtenidos de forma segura.")
                sock.close()

                # 6. Descifrado del archivo multimedia
                aes_archivo = Cipher(algorithms.AES(key_contenido), modes.CBC(vec_contenido))
                decryptor_archivo = aes_archivo.decryptor()

                with open(ruta_archivo, 'rb') as f_in:
                    datos_cifrados = f_in.read()

                if nombre_fichero.lower().endswith('mp4'):
                    # Descifrado directo para contenedor de vídeo
                    datos_des = decryptor_archivo.update(datos_cifrados)
                    with open(ruta_archivo, 'wb') as f_out:
                        f_out.write(datos_des)
                    print(f"[CLIENT-DRM] Vídeo '{nombre_fichero}' descifrado con éxito.")
                else:
                    # Descifrado con remoción de padding PKCS#7 para imágenes
                    datos_padded = decryptor_archivo.update(datos_cifrados) + decryptor_archivo.finalize()
                    try:
                        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
                        datos_finales = unpadder.update(datos_padded) + unpadder.finalize()
                    except ValueError:
                        datos_finales = datos_padded

                    with open(ruta_archivo, 'wb') as f_out:
                        f_out.write(datos_finales)
                    print(f"[CLIENT-DRM] Imagen '{nombre_fichero}' descifrada y des-padded con éxito.")

    except Exception as e:
        print(f"[CLIENT-DRM] Error durante el proceso de obtención de licencia o descifrado: {e}")


def list_files(sock: socket) -> None:
    """Envía comando LIST al servidor y muestra los ficheros disponibles."""
    formato = input("Escriba extensión (.jpg, .mp4, etc.) o 'all' para todos: ").strip() or "all"
    sock.send(f"LIST {formato}".encode('utf-8'))

    msj = sock.recv(2048).decode('utf-8', errors='ignore')
    if msj.startswith('201'):
        print("[CLIENT] No hay ficheros disponibles con ese criterio.")
        return

    print("\n--- CATÁLOGO DE FICHEROS DISPONIBLES ---")
    contador = 1
    while True:
        sock.send(b'Sigue')
        item = sock.recv(2048).decode('utf-8', errors='ignore').strip()
        if item == '205 FIN' or not item:
            break
        print(f"  {contador}. {item}")
        contador += 1
    print("----------------------------------------\n")


def get_file(sock: socket, filename: str) -> bool:
    """Descarga un archivo multimedia del servidor de contenidos a la carpeta downloads/."""
    ruta_destino = DOWNLOADS_DIR / filename
    sock.send(f"GET {filename}".encode('utf-8'))

    respuesta = sock.recv(2048).decode('utf-8', errors='ignore')
    if respuesta.startswith('401'):
        print(f"[CLIENT] Error: Archivo '{filename}' no encontrado en el servidor.")
        return False

    sock.send(b'OK')
    with open(ruta_destino, 'wb') as f_out:
        while True:
            chunk = sock.recv(2048)
            if chunk == b'FIN' or not chunk:
                break
            f_out.write(chunk)
            sock.send(b'Next')

    print(f"[CLIENT] Archivo '{filename}' descargado correctamente en {DOWNLOADS_DIR}")
    return True


def ejecutar_cliente(content_host: str = '', content_port: int = 8000,
                      license_host: str = '', license_port: int = 9000) -> None:
    """Bucle principal de la interfaz de usuario en consola."""
    host_c = content_host or gethostbyname(gethostname())
    sock = socket(AF_INET, SOCK_STREAM)

    try:
        sock.connect((host_c, content_port))
    except Exception as e:
        print(f"[CLIENT] No se pudo conectar al Servidor de Contenidos ({host_c}:{content_port}): {e}")
        return

    print(f"Conectado al Servidor de Contenidos en {host_c}:{content_port}")
    usuario = input("Ingrese su nombre de usuario para la sesión: ").strip() or "invitado"
    sock.send(f"USER {usuario}".encode('utf-8'))
    print(sock.recv(2048).decode('utf-8', errors='ignore'))

    while True:
        comando = input("\nIngrese comando (LIST, GET, EXIT): ").strip().upper()

        if comando == 'LIST':
            list_files(sock)

        elif comando == 'GET':
            fichero = input("Nombre del fichero a solicitar: ").strip()
            if not fichero:
                continue

            exito = get_file(sock, fichero)
            if exito:
                ruta_descargada = DOWNLOADS_DIR / fichero
                cifrado = es_archivo_aes_encriptado(ruta_descargada)
                if cifrado:
                    print("[CLIENT] El contenido está protegido (Cifrado AES). Iniciando negociación DRM...")
                    hilo = threading.Thread(
                        target=desencriptar_archivo,
                        args=(fichero, license_host, license_port)
                    )
                    hilo.start()
                    hilo.join()
                else:
                    print("[CLIENT] El contenido es de acceso libre (sin cifrado). Listo para reproducir.")

        elif comando == 'EXIT':
            sock.send(b'QUIT')
            print("[CLIENT] Sesión finalizada.")
            break
        else:
            print("[CLIENT] Comando no reconocido. Opciones: LIST, GET, EXIT.")

    sock.close()


if __name__ == "__main__":
    ejecutar_cliente()
