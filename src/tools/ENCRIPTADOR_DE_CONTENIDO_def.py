from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.padding import PKCS7
import os
import ast

def buscar_clave(posicion, lineas):
    """Busca la clave correspondiente a una posición en el archivo de claves."""
    for i in range(0, len(lineas), 2):
        if (lineas[i].strip())[:-1] == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None

def buscar_vector(posicion, lineas):
    """Busca el vector correspondiente a una posición en el archivo de vectores."""
    for i in range(0, len(lineas), 2):
        if (lineas[i].strip())[:-1] == posicion:
            return ast.literal_eval(lineas[i + 1].strip())
    return None
def cargar_archivo(ruta_archivo):
    """Carga el contenido de un archivo y lo devuelve como una lista de líneas."""
    if os.path.exists(ruta_archivo):
        with open(ruta_archivo, "r") as archivo:
            return archivo.readlines()
    else:
        print(f"[SERVIDOR] Archivo {ruta_archivo} no encontrado.")
        return []
key = b"\xc9\x019\xe9\xbci\xbb\x9f\x8f\xe9B\x86DW\xab="
v= b"\xf5\xc7\x19\x843\xf1\r\x91\xdfV\xca-\x88*r\x83"
aesCipher_CBC = Cipher(algorithms.AES(key),modes.CBC(v))
aesEncryptor_CBC = aesCipher_CBC.encryptor()
aesDecryptor_CBC = aesCipher_CBC.decryptor()

img=open('foto_dani.jpeg','rb')
mensaje= img.read()


#encriptado
texto_en=aesEncryptor_CBC.update(mensaje)

img_fin=open('foto_dani_prueba.jpeg','wb')
img_fin.write(texto_en)
img_fin.close()
print('Mensaje enviado: ',mensaje)
print('Encriptado con los huecos si fuese necesario: ',texto_en) #pasar de bytes a hexa

import time
def desencriptar(nombreFichero):
    '''#Key y vector
    aesCipher_archivo = Cipher(algorithms.AES(key),modes.CBC(v))
    aesDesEncryptor_archivo = aesCipher_archivo.decryptor()
    print(nombreFichero)
    #desencriptador_del_archivo
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_archivo = os.path.join(directorio_actual, nombreFichero)
    archivo = open(ruta_archivo,'rb')
    archivo_des = aesDesEncryptor_archivo.update(archivo.read())
    Fin = open(ruta_archivo,'wb')
    Fin.write(archivo_des)
    print('Fichero copiado')'''
    # Crear el objeto de cifrado AES en modo CBC
    aesCipher_archivo = Cipher(algorithms.AES(key), modes.CBC(v))
    aesDesEncryptor_archivo = aesCipher_archivo.decryptor()

    print(nombreFichero)

    # Obtener la ruta del archivo
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_archivo = os.path.join(directorio_actual, 'archivosrecibidos/' + nombreFichero)
    with open(nombreFichero, 'rb') as archivo:
        datos_encriptados = archivo.read()
        archivo_desencriptado_padded = aesDesEncryptor_archivo.update(datos_encriptados) + aesDesEncryptor_archivo.finalize()

                    # Quitar el padding utilizando PKCS7
    try:
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        archivo_desencriptado = unpadder.update(archivo_desencriptado_padded) + unpadder.finalize()
    except ValueError as e:
        print(f"Error al quitar el padding: {e}")
        archivo_desencriptado = None

    if archivo_desencriptado:
                        # Guardar el archivo desencriptado sin padding
        with open(ruta_archivo, 'wb') as archivo_salida:
            archivo_salida.write(archivo_desencriptado)
            print("El archivo ha sido desencriptado y el padding eliminado correctamente.")
    else:
        print("El archivo no se pudo desencriptar correctamente.")

                    
        print('Fichero copiado')

desencriptar('foto_dani_prueba.jpeg')
    
                    
            #
