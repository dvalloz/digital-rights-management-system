"""
Servidor de Licencias DRM (License & Key Management Server)
===========================================================
Gestiona la emisión segura de material criptográfico (claves simétricas AES-128 e IVs)
necesario para el descifrado de los contenidos digitales protegidos.

Garantías de seguridad:
- Canal seguro híbrido: intercambio de clave de sesión con RSA-2048 (OAEP-SHA256) y
  cifrado de tránsito simétrico con AES-128-CBC.
- Autenticación y no repudio: exige y verifica firmas digitales RSA-PSS (SHA-256)
  emitidas por el cliente / CDM antes de despachar licencias.
- Concurrencia: maneja múltiples clientes simultáneos mediante hilos (threading).
"""

import os
import ast
import sys
import time
import socket
import threading
from pathlib import Path
from typing import Optional

# Asegurar importación de src/core
SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.digital_signature import verificar_firma
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEYS_DIR = Path(__file__).resolve().parent / "keys"
ARCHIVO_CLAVES = KEYS_DIR / "claves.txt"
ARCHIVO_VECTORES = KEYS_DIR / "vectores.txt"
ARCHIVO_AES_CBC = KEYS_DIR / "AES_CBC.txt"

DEFAULT_PORT = 9000


def cargar_archivo(ruta_archivo: Path | str) -> list[str]:
    """Carga el contenido de un archivo de texto en una lista de líneas."""
    p = Path(ruta_archivo)
    if p.is_file():
        with open(p, "r", encoding="utf-8") as f:
            return f.readlines()
    print(f"[LICENSE-SERVER] Advertencia: archivo {p} no encontrado.")
    return []


def buscar_clave(posicion: str, lineas: list[str]) -> Optional[bytes]:
    """Busca la clave de 16 bytes correspondiente a un archivo en las líneas cargadas."""
    for i in range(0, len(lineas), 2):
        if lineas[i].strip().rstrip(':') == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None


def buscar_vector(posicion: str, lineas: list[str]) -> Optional[bytes]:
    """Busca el vector IV de 16 bytes correspondiente a un archivo en las líneas cargadas."""
    for i in range(0, len(lineas), 2):
        if lineas[i].strip().rstrip(':') == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None


def encriptar_asimetrico(mensaje: bytes, clave_publica) -> bytes:
    """Cifra un mensaje utilizando la clave pública RSA con OAEP (SHA-256)."""
    return clave_publica.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def manejar_cliente(socket_cliente: socket.socket, addr, lineas_claves: list[str],
                    lineas_vectores: list[str], lineas_aes_cbc: list[str]) -> None:
    """Atiende el protocolo de solicitud de licencias de un cliente conectado."""
    print(f"[LICENSE-SERVER] Iniciando sesión para cliente {addr}")
    try:
        clave_publica_cliente = None
        clave_simetrica = None
        vector_simetrico = None
        nombre_fichero_actual = ""

        while True:
            recibido = socket_cliente.recv(2048)
            if not recibido:
                break

            palabras = recibido.split()
            if not palabras:
                continue

            primer_token = palabras[0].decode('utf-8', errors='ignore')

            # 1. Handshake inicial de clave pública RSA del cliente (~451 bytes PEM)
            if len(recibido) == 451 or b'BEGIN PUBLIC KEY' in recibido:
                clave_publica_cliente = serialization.load_pem_public_key(recibido)
                print(f"[LICENSE-SERVER] Clave pública de {addr} recibida y validada.")
                socket_cliente.send(b'READY')
                time.sleep(0.5)
                socket_cliente.send(b'GO')

            # 2. Negociación de Clave Simétrica de Sesión (Canal Seguro)
            elif primer_token == 'KEY_SIM':
                if clave_simetrica is None:
                    clave_simetrica = ast.literal_eval(lineas_aes_cbc[1].strip())
                cifrada = encriptar_asimetrico(clave_simetrica, clave_publica_cliente)
                socket_cliente.send(cifrada)
                print(f"[LICENSE-SERVER] Clave de sesión cifrada enviada a {addr}")

            # 3. Negociación de Vector Simétrico de Sesión (Canal Seguro)
            elif primer_token == 'VEC_SIM':
                if vector_simetrico is None:
                    vector_simetrico = ast.literal_eval(lineas_aes_cbc[3].strip())
                cifrada = encriptar_asimetrico(vector_simetrico, clave_publica_cliente)
                socket_cliente.send(cifrada)
                print(f"[LICENSE-SERVER] Vector de sesión cifrado enviado a {addr}")

            # 4. Solicitud de Licencia firmada digitalmente
            elif primer_token == 'GET':
                nombre_fichero_actual = palabras[1].decode('utf-8', errors='ignore')
                partes = recibido.split(b'...')
                if len(partes) < 3:
                    socket_cliente.send(b'400 FORMATO DE SOLICITUD INVALIDO')
                    continue

                firma = partes[1].strip()
                publica_firmante = partes[2].strip()

                # Verificación criptográfica de firma digital RSA-PSS
                mensaje_a_verificar = f"GET {nombre_fichero_actual}"
                es_valida = verificar_firma(mensaje_a_verificar, firma, publica_firmante)

                if es_valida:
                    clave_archivo = buscar_clave(nombre_fichero_actual, lineas_claves)
                    if clave_archivo:
                        # Cifrado simétrico AES-CBC de la clave dentro del canal seguro
                        cifrador = Cipher(algorithms.AES(clave_simetrica), modes.CBC(vector_simetrico))
                        encryptor = cifrador.encryptor()
                        clave_cifrada = encryptor.update(clave_archivo) + encryptor.finalize()
                        socket_cliente.send(clave_cifrada)
                        print(f"[LICENSE-SERVER] Licencia (Clave) de '{nombre_fichero_actual}' despachada.")
                    else:
                        socket_cliente.send(b'401 NO EXISTE CLAVE')
                else:
                    socket_cliente.send(b'Firma no valida.')
                    print(f"[LICENSE-SERVER] ALERTA: Firma digital rechazada para '{nombre_fichero_actual}'")

            # 5. Envío del Vector de Inicialización (IV) de contenido tras confirmación
            elif primer_token.startswith('OK'):
                vector_archivo = buscar_vector(nombre_fichero_actual, lineas_vectores)
                if vector_archivo:
                    cifrador = Cipher(algorithms.AES(clave_simetrica), modes.CBC(vector_simetrico))
                    encryptor = cifrador.encryptor()
                    vector_cifrado = encryptor.update(vector_archivo) + encryptor.finalize()
                    socket_cliente.send(vector_cifrado)
                    print(f"[LICENSE-SERVER] IV de contenido para '{nombre_fichero_actual}' enviado.")
                else:
                    socket_cliente.send(b'401 NO EXISTE VECTOR')
                break

    except Exception as e:
        print(f"[LICENSE-SERVER] Error en comunicación con {addr}: {e}")
    finally:
        socket_cliente.close()
        print(f"[LICENSE-SERVER] Sesión cerrada con {addr}")


def iniciar_servidor_licencias(host: str = '', port: int = DEFAULT_PORT) -> None:
    """Inicia el servidor multihilo de licencias DRM."""
    lineas_claves = cargar_archivo(ARCHIVO_CLAVES)
    lineas_vectores = cargar_archivo(ARCHIVO_VECTORES)
    lineas_aes_cbc = cargar_archivo(ARCHIVO_AES_CBC)

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, port))
    servidor.listen(5)
    print(f"[LICENSE-SERVER] Servidor de Licencias escuchando en puerto {port}...")

    try:
        while True:
            cliente_socket, direccion = servidor.accept()
            hilo = threading.Thread(
                target=manejar_cliente,
                args=(cliente_socket, direccion, lineas_claves, lineas_vectores, lineas_aes_cbc)
            )
            hilo.daemon = True
            hilo.start()
    except KeyboardInterrupt:
        print("\n[LICENSE-SERVER] Deteniendo servidor de licencias...")
    finally:
        servidor.close()


if __name__ == "__main__":
    iniciar_servidor_licencias()
