"""Módulo de alias para mantener compatibilidad con los nombres originales."""
from .digital_signature import generar_claves, firma_digital, verificar_firma

__all__ = ["generar_claves", "firma_digital", "verificar_firma"]
