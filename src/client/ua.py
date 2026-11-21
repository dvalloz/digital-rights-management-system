"""
User Agent (UA) - Aplicación de Usuario - Fase III
==================================================
Representa el frontal del usuario (como un navegador o app de streaming).
Orquesta la descarga del contenido multimedia desde el Servidor de Contenidos,
la intermediación con el CDM local (8002) y con el Servidor de Licencias (9000).

Principios de diseño:
- La UA nunca tiene acceso a la clave privada del cliente (custodiada por el CDM).
- La UA nunca tiene acceso a las claves simétricas de descifrado ni descifra el contenido;
  únicamente reenvía blobs cifrados entre el CDM y el License Server.
"""

import os
import sys
import time
import threading
from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, gethostname

SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.crypto_detect import es_archivo_aes_encriptado
from core.digital_signature import generar_claves
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DOWNLOADS_DIR = Path(__file__).resolve().parent / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Par de claves de la UA para comunicarse de forma segura con el CDM y el Servidor de Licencias
CLAVE_PRIVADA_UA, CLAVE_PUBLICA_PEM_UA = generar_claves()


def des_asi(mensaje_encriptado: bytes, clave_privada) -> bytes:
    """Descifra mensajes asimétricos con la clave privada de la UA."""
    return clave_privada.decrypt(
        mensaje_encriptado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def intermediar_licencia(sock_cdm: socket, mensaje_firmado: bytes, sock_licencias: socket) -> None:
    """
    Reenvía el mensaje de solicitud de licencia firmado al Servidor de Licencias,
    obtiene la clave e IV cifrados y se los suministra al CDM.
    """
    try:
        # Reenviar al servidor de licencias
        sock_licencias.send(mensaje_firmado)

        # Recibir clave de contenido cifrada
        clave_cifrada = sock_licencias.recv(2048)

        # Reenviarla al CDM
        sock_cdm.send(clave_cifrada)
        conf = sock_cdm.recv(2048).decode('utf-8', errors='ignore')

        if conf.startswith('OK'):
            sock_licencias.send(b'OK')
            vector_cifrado = sock_licencias.recv(2048)
            sock_cdm.send(vector_cifrado)

        print("[UA] Intercambio de licencia entre Servidor de Licencias y CDM completado.")
    except Exception as e:
        print(f"[UA] Error en la intermediación de licencia: {e}")


def comunicar_con_cdm(nombre_fichero: str, license_host: str = '', license_port: int = 9000,
                      cdm_host: str = '', cdm_port: int = 8002) -> None:
    """Establece canal con el CDM y con el Servidor de Licencias para tramitar el descifrado."""
    host_c = cdm_host or gethostbyname(gethostname())
    host_l = license_host or gethostbyname(gethostname())

    try:
        # 1. Conexión con Servidor de Licencias
        sock_lic = socket(AF_INET, SOCK_STREAM)
        sock_lic.connect((host_l, license_port))

        # 2. Conexión con CDM
        sock_cdm = socket(AF_INET, SOCK_STREAM)
        sock_cdm.connect((host_c, cdm_port))

        # Handshake con CDM
        sock_cdm.send(CLAVE_PUBLICA_PEM_UA)
        time.sleep(0.5)
        conf_cdm = sock_cdm.recv(2048).decode('utf-8', errors='ignore')

        if 'READY' in conf_cdm:
            empieza_cdm = sock_cdm.recv(2048).decode('utf-8', errors='ignore')
            if 'GO' in empieza_cdm:
                # Handshake con Servidor de Licencias
                sock_lic.send(CLAVE_PUBLICA_PEM_UA)
                time.sleep(0.5)
                conf_lic = sock_lic.recv(2048).decode('utf-8', errors='ignore')
                empieza_lic = sock_lic.recv(2048).decode('utf-8', errors='ignore')

                # Obtener claves simétricas de sesión con ambos
                sock_cdm.send(b'KEY_SIM')
                sock_lic.send(b'KEY_SIM')
                key_sim_cif_cdm = sock_cdm.recv(2048)
                key_sim_cif_lic = sock_lic.recv(2048)

                sock_cdm.send(b'VEC_SIM')
                sock_lic.send(b'VEC_SIM')
                vec_sim_cif_cdm = sock_cdm.recv(2048)
                vec_sim_cif_lic = sock_lic.recv(2048)

                # Solicitar al CDM que elabore y firme la solicitud
                sock_cdm.send(f"GET {nombre_fichero}".encode('utf-8'))
                mensaje_firmado = sock_cdm.recv(2048)

                # Reenviar al Servidor de Licencias y orquestar
                hilo_licencias = threading.Thread(
                    target=intermediar_licencia,
                    args=(sock_cdm, mensaje_firmado, sock_lic)
                )
                hilo_licencias.start()
                hilo_licencias.join()

    except Exception as e:
        print(f"[UA] Error en la orquestación con CDM / Licencias: {e}")


def list_files(sock: socket) -> None:
    """Envía comando LIST al servidor y muestra los ficheros disponibles."""
    formato = input("Escriba extensión (.jpg, .mp4, etc.) o 'all' para todos: ").strip() or "all"
    sock.send(f"LIST {formato}".encode('utf-8'))

    msj = sock.recv(2048).decode('utf-8', errors='ignore')
    if msj.startswith('201'):
        print("[UA] No hay ficheros disponibles con ese criterio.")
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
        print(f"[UA] Error: Archivo '{filename}' no encontrado en el servidor.")
        return False

    sock.send(b'OK')
    with open(ruta_destino, 'wb') as f_out:
        while True:
            chunk = sock.recv(2048)
            if chunk == b'FIN' or not chunk:
                break
            f_out.write(chunk)
            sock.send(b'Next')

    print(f"[UA] Archivo '{filename}' descargado en {DOWNLOADS_DIR}")
    return True


def ejecutar_ua(content_host: str = '', content_port: int = 8000,
                 license_host: str = '', license_port: int = 9000,
                 cdm_host: str = '', cdm_port: int = 8002) -> None:
    """Bucle principal de la interfaz de la User Agent."""
    host_c = content_host or gethostbyname(gethostname())
    sock = socket(AF_INET, SOCK_STREAM)

    try:
        sock.connect((host_c, content_port))
    except Exception as e:
        print(f"[UA] Error al conectar al Servidor de Contenidos ({host_c}:{content_port}): {e}")
        return

    print(f"[UA] Conectado al Servidor de Contenidos ({host_c}:{content_port})")
    usuario = input("Ingrese su identificador de usuario: ").strip() or "invitado"
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
                    print("[UA] Contenido protegido detectado. Delegando negociación de licencia al CDM...")
                    hilo = threading.Thread(
                        target=comunicar_con_cdm,
                        args=(fichero, license_host, license_port, cdm_host, cdm_port)
                    )
                    hilo.start()
                    hilo.join()
                else:
                    print("[UA] Contenido en claro disponible para reproducción.")

        elif comando == 'EXIT':
            sock.send(b'QUIT')
            print("[UA] Sesión finalizada.")
            break
        else:
            print("[UA] Comando inválido. Opciones: LIST, GET, EXIT.")

    sock.close()


if __name__ == "__main__":
    ejecutar_ua()
