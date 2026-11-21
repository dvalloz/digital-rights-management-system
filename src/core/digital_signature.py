"""
Módulo de Firma Digital y Criptografía Asimétrica RSA
=====================================================
Implementa la generación de pares de claves RSA (2048 bits), la emisión de firmas
digitales probabilísticas (RSA-PSS con SHA-256) y su correspondiente verificación.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generar_claves(tamano_clave: int = 2048, exponente: int = 65537) -> Tuple[rsa.RSAPrivateKey, bytes]:
    """
    Genera un par de claves RSA asimétricas.
    
    Args:
        tamano_clave: Tamaño en bits de la clave (por defecto 2048 bits).
        exponente: Exponente público e (por defecto 65537).
        
    Returns:
        Tupla con (clave_privada, clave_publica_pem_bytes).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=exponente,
        key_size=tamano_clave
    )
    clave_publica_pem = clave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return clave_privada, clave_publica_pem


def firma_digital(mensaje: str | bytes, clave_privada: rsa.RSAPrivateKey) -> bytes:
    """
    Firma digitalmente un mensaje utilizando RSA-PSS con SHA-256.
    
    Args:
        mensaje: Contenido a firmar (str o bytes).
        clave_privada: Clave privada RSA del emisor.
        
    Returns:
        Firma digital en formato bytes.
    """
    if isinstance(mensaje, str):
        datos = mensaje.encode('utf-8')
    else:
        datos = mensaje

    firma = clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma


def verificar_firma(mensaje: str | bytes, firma: bytes, clave_publica_pem: bytes) -> bool:
    """
    Verifica la autenticidad e integridad de una firma digital RSA-PSS.
    
    Args:
        mensaje: Contenido original que fue firmado.
        firma: Bytes de la firma digital recibida.
        clave_publica_pem: Clave pública del firmante codificada en formato PEM.
        
    Returns:
        True si la firma es válida, False en caso contrario.
    """
    try:
        if isinstance(mensaje, str):
            datos = mensaje.encode('utf-8')
        else:
            datos = mensaje

        clave_pub = serialization.load_pem_public_key(clave_publica_pem)
        clave_pub.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[SIGNATURE] Firma digital verificada con éxito (Válida).")
        return True
    except Exception as e:
        print(f"[SIGNATURE] Fallo en la verificación de firma: {e}")
        return False
