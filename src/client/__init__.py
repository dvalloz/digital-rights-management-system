"""Módulos del cliente DRM: Cliente integrado (Fases I y II) y UA + CDM (Fase III)."""
from .cliente import ejecutar_cliente
from .ua import ejecutar_ua
from .cdm import iniciar_cdm

__all__ = ["ejecutar_cliente", "ejecutar_ua", "iniciar_cdm"]
