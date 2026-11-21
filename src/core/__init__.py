"""
Paquete core del sistema DRM: criptografía, firmas digitales y esteganografía.
"""

from .crypto_detect import es_archivo_aes_encriptado
from .digital_signature import generar_claves, firma_digital, verificar_firma
from .watermark import añadir_marcad, añadir_marcae

__all__ = [
    "es_archivo_aes_encriptado",
    "generar_claves",
    "firma_digital",
    "verificar_firma",
    "añadir_marcad",
    "añadir_marcae",
]
