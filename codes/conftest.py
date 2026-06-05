"""Configuración de pytest: añade codes/ a sys.path para que los tests puedan importar src.*"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
