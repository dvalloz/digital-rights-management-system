"""
Servidor de Contenidos Multimedia con Watermarking Forense en Tiempo Real
=========================================================================
Distribuye archivos multimedia (imágenes y vídeos) a los clientes a través de un
protocolo de aplicación sobre sockets TCP. Integra inyección dinámica de marcas
de agua forenses basadas en la identidad del usuario solicitante.
"""

import os
import sys
from pathlib import Path
from socket import socket, AF_INET, SOCK_STREAM

# Asegurar importación de src/core
SRC_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.watermark import añadir_marcad, añadir_marcae
from core.crypto_detect import es_archivo_aes_encriptado

MEDIA_DIR = Path(__file__).resolve().parent / "media"
DEFAULT_PORT = 8000


def send_list(client_socket: socket, extension: str = 'all') -> None:
    """Envía al cliente el catálogo de archivos disponibles en el servidor."""
    if not MEDIA_DIR.exists():
        client_socket.send(b'201 NO HAY FICHEROS')
        return

    filepath = [f.name for f in MEDIA_DIR.iterdir() if f.is_file() and not f.name.startswith('.')]

    client_socket.send(b'200 INICIO ENVIO LISTADO\n')
    client_socket.recv(2048)  # Espera ACK del cliente

    if extension != 'all':
        ext = extension.lower().lstrip('.')
        filepath = [f for f in filepath if f.lower().endswith(f".{ext}")]

    if not filepath:
        client_socket.send(b'201 NO HAY FICHEROS')
        return

    for filename in sorted(filepath):
        client_socket.send(filename.encode('utf-8'))
        client_socket.recv(2048)  # ACK por elemento

    client_socket.send(b'205 FIN')
    print(f"[CONTENT-SERVER] Listado enviado: {len(filepath)} archivo(s).")


def send_file(client_socket: socket, filename: str, usuario: str) -> None:
    """
    Procesa y transmite el archivo multimedia solicitado aplicando watermarking si es imagen.
    """
    file_path = MEDIA_DIR / filename
    if not file_path.is_file():
        client_socket.send(b'401 FICHERO NO ENCONTRADO')
        print(f"[CONTENT-SERVER] Archivo no encontrado: {filename}")
        return

    is_image = filename.lower().endswith(('jpg', 'png', 'jfif', 'jpeg'))
    encrypted = es_archivo_aes_encriptado(file_path)

    print(f"[CONTENT-SERVER] Petición de '{filename}' por usuario '{usuario}'. Cifrado: {encrypted}")

    if is_image:
        # Inserción dinámica de marca de agua según el estado criptográfico
        if encrypted:
            filebytes = añadir_marcae(file_path, usuario)
        else:
            filebytes = añadir_marcad(file_path, usuario)

        if filebytes is None:
            # Fallback en caso de incidencia con PIL: transmitir archivo directo
            with open(file_path, 'rb') as f:
                filebytes = f.read()

        size = len(filebytes)
        client_socket.send(f'200 LONGITUD CONTENIDO: {size}\n'.encode('utf-8'))
        client_socket.recv(2048)  # ACK del cliente

        # Transmisión por chunks de 2048 bytes con control de flujo
        for i in range(0, size, 2048):
            trozo = filebytes[i:i + 2048]
            client_socket.sendall(trozo)
            client_socket.recv(2048)

        client_socket.send(b'FIN')
        print(f"[CONTENT-SERVER] Imagen '{filename}' con watermark enviada ({size} bytes).")

    else:
        # Transmisión de vídeo (sin marca de agua de imagen)
        size = file_path.stat().st_size
        client_socket.send(f'200 LONGITUD CONTENIDO: {size}\n'.encode('utf-8'))
        client_socket.recv(2048)

        with open(file_path, 'rb') as f:
            while True:
                trozo = f.read(2048)
                if not trozo:
                    break
                client_socket.sendall(trozo)
                client_socket.recv(2048)

        client_socket.send(b'FIN')
        print(f"[CONTENT-SERVER] Vídeo '{filename}' enviado con éxito ({size} bytes).")


def iniciar_servidor_contenidos(host: str = '', port: int = DEFAULT_PORT) -> None:
    """Inicia el socket listener del Servidor de Contenidos."""
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[CONTENT-SERVER] Escuchando en el puerto {port}...")

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            print(f"[CONTENT-SERVER] Cliente conectado desde {client_addr}")
            usuario = "anónimo"

            while True:
                data = client_socket.recv(2048)
                if not data:
                    break
                message = data.decode('utf-8', errors='ignore').strip()
                if not message:
                    continue

                partes = message.split()
                comando = partes[0].upper()

                if comando == 'USER':
                    usuario = partes[1] if len(partes) > 1 else 'anonimo'
                    client_socket.send(b'100 USUARIO REGISTRADO CON EXITO\n')
                    print(f"[CONTENT-SERVER] Usuario autenticado: {usuario}")

                elif comando == 'LIST':
                    param = partes[1] if len(partes) > 1 else 'all'
                    send_list(client_socket, param)

                elif comando == 'GET':
                    if len(partes) > 1:
                        send_file(client_socket, partes[1], usuario)
                    else:
                        client_socket.send(b'400 COMANDO INVALIDO')

                elif comando == 'QUIT':
                    print(f"[CONTENT-SERVER] Cierre de sesión para {client_addr}")
                    break

            client_socket.close()

    except KeyboardInterrupt:
        print("\n[CONTENT-SERVER] Deteniendo servidor...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    iniciar_servidor_contenidos()
