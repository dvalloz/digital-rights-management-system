from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Generar clave y vector aleatorios
key = os.urandom(16)  # Clave AES de 128 bits
v = os.urandom(16)    # Vector de inicialización (IV) de 128 bits
print("Clave:", key)
print("IV:", v)

# Crear el cifrador AES en modo CBC
aesCipher_CBC = Cipher(algorithms.AES(key), modes.CBC(v))
aesEncryptor_CBC = aesCipher_CBC.encryptor()

# Ruta del video de entrada y salida
video_entrada = 'video_miguel.mp4'
video_salida = 'video1_miguel_e.mp4'

# Leer el video por bloques y cifrar
with open(video_entrada, 'rb') as entrada, open(video_salida, 'wb') as salida:
    # Padding para asegurar que el último bloque tiene un tamaño múltiplo de 16 bytes
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    
    while True:
        bloque = entrada.read(1024)  # Leer en bloques de 1 KB
        if not bloque:  # Si no hay más datos, salir del bucle
            break
        if len(bloque) % 16 != 0:
            bloque = padder.update(bloque) + padder.finalize()
        texto_en = aesEncryptor_CBC.update(bloque)
        salida.write(texto_en)

    # Finalizar el cifrado
    texto_en = aesEncryptor_CBC.finalize()
    salida.write(texto_en)

print(f"Video encriptado guardado en '{video_salida}'")
