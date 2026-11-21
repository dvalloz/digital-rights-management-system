import os
#Este archivo simplemente contiene una función que nos ayudará
#a determinar si el archivo esta encriptado con AES o no, lo hacemos simplemente leyendo los 32 primos bytes
#Y verificando si el encabezado tiene patrones ASCII o conocidos
#Si contiene texto ASCII probablemente no esta encriptado
def es_archivo_aes_encriptado(ruta_archivo):
    try:
        with open(ruta_archivo, 'rb') as archivo:
            contenido = archivo.read(32)  # Leer los primeros 32 bytes (suficiente para análisis inicial)
            
            # Verificar si el archivo tiene patrones ASCII o encabezados conocidos
            if contenido.isascii():
                print("El archivo contiene texto ASCII, probablemente no está cifrado.")
                return False
            
            # Verificar encabezados de formatos comunes (por ejemplo, JPEG, PNG, MP4, etc.)
            encabezados_comunes = {
                b'\xFF\xD8\xFF': "JPEG/JFIF/JPG",
                b'\x89PNG\r\n\x1a\n': "PNG",
                b'\x00\x00\x00\x18ftyp': "MP4",
            }
            for firma, formato in encabezados_comunes.items():
                if contenido.startswith(firma):
                    print(f"El archivo parece ser un {formato} no cifrado.")
                    return False
            
            # Verificar tamaño del archivo (debe ser múltiplo de 16 para AES CBC)
            tamaño_archivo = os.path.getsize(ruta_archivo)
            if tamaño_archivo % 16 != 0:
                print("El tamaño del archivo no es múltiplo de 16, probablemente no está cifrado con AES CBC.")
                return False

            # Si llega aquí, el archivo tiene alta probabilidad de estar cifrado
            print("El archivo parece estar cifrado con AES CBC.")
            return True
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")
        return None

#Ruta al archivo
#ruta = "foto2.jpg"
#if es_archivo_aes_encriptado(ruta):
#    print("El archivo está cifrado con AES CBC.")
#else:
#    print("El archivo no parece estar cifrado.")
