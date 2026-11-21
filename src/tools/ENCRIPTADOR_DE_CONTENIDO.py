from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


key = b"\xc9\x019\xe9\xbci\xbb\x9f\x8f\xe9B\x86DW\xab="
v= b'\xf5\xc7\x19\x843\xf1\r\x91\xdfV\xca-\x88*r\x83'
aesCipher_CBC = Cipher(algorithms.AES(key),modes.CBC(v))
aesEncryptor_CBC = aesCipher_CBC.encryptor()
aesDecryptor_CBC = aesCipher_CBC.decryptor()

img=open('foto_dani.jpeg','rb')
mensaje= img.read()


#encriptado
texto_en=aesEncryptor_CBC.update(mensaje)

img_fin=open('foto_dani_e.jpeg','wb')
img_fin.write(texto_en)
img_fin.close()
print('Mensaje enviado: ',mensaje)
print('Encriptado con los huecos si fuese necesario: ',texto_en) #pasar de bytes a hexa

import time
def desencriptar(nombreFichero):
    #Key y vector
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
    print('Fichero copiado')

#desencriptar('foto_dani_prueba.jpeg')
    
                    
            #
