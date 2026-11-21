"""
Content Decryption Module (CDM) - Fase III
==========================================
Componente criptográfico aislado (Sandbox) que simula el CDM de la especificación
W3C Encrypted Media Extensions (EME).

Responsabilidades de seguridad:
- Almacena y custodia en un entorno seguro las claves criptográficas privadas del cliente.
- Genera y firma digitalmente las solicitudes de licencia (License Request) mediante RSA-PSS.
- Procesa las respuestas de licencia del Servidor de Licencias intermediadas por la UA.
- Desencripta de forma autónoma el contenido multimedia protegido sin exponer las claves
  maestras ni el contenido sin cifrar a la aplicación de usuario (UA).
"""

import os
import ast
import sys
import time
import socket
import threading
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.digital_signature import firma_digital
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

DOWNLOADS_DIR = Path(__file__).resolve().parent / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

KEYS_DIR = SRC_DIR / "license_server" / "keys"
ARCHIVO_AES_CBC = KEYS_DIR / "AES_CBC.txt"

DEFAULT_CDM_PORT = 8002

# Clave privada exclusiva del entorno CDM
CLAVE_PRIVADA_CDM = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CLAVE_PUBLICA_CDM = CLAVE_PRIVADA_CDM.public_key()
CLAVE_PUBLICA_PEM_CDM = CLAVE_PUBLICA_CDM.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def encriptar_asimetrico(mensaje: bytes, clave_publica) -> bytes:
    """Cifra simétrica o asimétricamente hacia la UA."""
    return clave_publica.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def des_asi(mensaje_encriptado: bytes, clave_privada) -> bytes:
    """Descifra con la clave privada del CDM."""
    return clave_privada.decrypt(
        mensaje_encriptado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def cargar_lineas_aes():
    if ARCHIVO_AES_CBC.exists():
        with open(ARCHIVO_AES_CBC, "r", encoding="utf-8") as f:
            return f.readlines()
    return []


def manejar_ua(socket_ua: socket.socket, addr) -> None:
    """Gestiona las peticiones de descifrado y firma enviadas por la UA."""
    print(f"[CDM] Conexión establecida con User Agent en {addr}")
    lineas_aes = cargar_lineas_aes()

    try:
        clave_publica_ua = None
        clave_simetrica = None
        vector_simetrico = None

        while True:
            recibido = socket_ua.recv(2048)
            if not recibido:
                break

            palabras = recibido.split()
            primer_token = palabras[0].decode('utf-8', errors='ignore') if palabras else ""

            # 1. Handshake de clave pública de la UA
            if len(recibido) == 451 or b'BEGIN PUBLIC KEY' in recibido:
                clave_publica_ua = serialization.load_pem_public_key(recibido)
                socket_ua.send(b'READY')
                time.sleep(0.5)
                socket_ua.send(b'GO')
                print("[CDM] Handshake de clave pública completado.")

            # 2. Establecer clave simétrica entre UA y CDM
            elif primer_token == 'KEY_SIM':
                if clave_simetrica is None:
                    clave_simetrica = ast.literal_eval(lineas_aes[1].strip())
                socket_ua.send(encriptar_asimetrico(clave_simetrica, clave_publica_ua))

            # 3. Establecer vector simétrico entre UA y CDM
            elif primer_token == 'VEC_SIM':
                if vector_simetrico is None:
                    vector_simetrico = ast.literal_eval(lineas_aes[3].strip())
                socket_ua.send(encriptar_asimetrico(vector_simetrico, clave_publica_ua))

            # 4. Solicitud de firma de License Request desde la UA
            elif primer_token == 'GET':
                nombre_fichero = palabras[1].decode('utf-8', errors='ignore')
                print(f"[CDM] Generando solicitud de licencia firmada para '{nombre_fichero}'...")

                firma = firma_digital(f"GET {nombre_fichero}", CLAVE_PRIVADA_CDM)
                mensaje_firmado = f"GET {nombre_fichero}".encode('utf-8') + b' ...' + firma + b'...' + CLAVE_PUBLICA_PEM_CDM
                socket_ua.send(mensaje_firmado)

                # 5. La UA reenvía la respuesta cifrada del Servidor de Licencias al CDM
                key_cif = socket_ua.recv(2048)

                aes_comu = Cipher(algorithms.AES(clave_simetrica), modes.CBC(vector_simetrico))
                decryptor_comu = aes_comu.decryptor()
                key_contenido = decryptor_comu.update(key_cif) + decryptor_comu.finalize()

                if len(key_contenido) != 16:
                    print(f"[CDM] Clave recibida inválida ({len(key_contenido)} bytes).")
                    continue

                # Solicitar IV de contenido a la UA
                aes_comu2 = Cipher(algorithms.AES(clave_simetrica), modes.CBC(vector_simetrico))
                decryptor_comu2 = aes_comu2.decryptor()
                socket_ua.send(f"OK {nombre_fichero}".encode('utf-8'))

                v_cif = socket_ua.recv(2048)
                vec_contenido = decryptor_comu2.update(v_cif) + decryptor_comu2.finalize()

                # 6. Descifrado seguro directo por el CDM
                ruta_archivo = DOWNLOADS_DIR / nombre_fichero
                if ruta_archivo.is_file():
                    with open(ruta_archivo, 'rb') as f_in:
                        datos_cifrados = f_in.read()

                    aes_archivo = Cipher(algorithms.AES(key_contenido), modes.CBC(vec_contenido))
                    decryptor_archivo = aes_archivo.decryptor()

                    if nombre_fichero.lower().endswith('mp4'):
                        datos_des = decryptor_archivo.update(datos_cifrados)
                    else:
                        datos_padded = decryptor_archivo.update(datos_cifrados) + decryptor_archivo.finalize()
                        try:
                            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
                            datos_des = unpadder.update(datos_padded) + unpadder.finalize()
                        except ValueError:
                            datos_des = datos_padded

                    with open(ruta_archivo, 'wb') as f_out:
                        f_out.write(datos_des)

                    print(f"[CDM] Éxito: Contenido '{nombre_fichero}' descifrado de forma segura en almacenamiento local.")
                else:
                    print(f"[CDM] Error: El archivo '{nombre_fichero}' no existe en {DOWNLOADS_DIR}")

    except Exception as e:
        print(f"[CDM] Error en sesión con UA: {e}")
    finally:
        socket_ua.close()
        print(f"[CDM] Sesión cerrada con {addr}")


def iniciar_cdm(host: str = '', port: int = DEFAULT_CDM_PORT) -> None:
    """Inicia el servicio CDM."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, port))
    servidor.listen(5)
    print(f"[CDM] Content Decryption Module activo en puerto {port}...")

    try:
        while True:
            cliente_socket, direccion = servidor.accept()
            hilo = threading.Thread(target=manejar_ua, args=(cliente_socket, direccion))
            hilo.daemon = True
            hilo.start()
    except KeyboardInterrupt:
        print("\n[CDM] Deteniendo CDM...")
    finally:
        servidor.close()


if __name__ == "__main__":
    iniciar_cdm()
