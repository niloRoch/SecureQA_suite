"""
Pacote utils do SecureQA Suite

Este módulo agrega classes utilitárias:
- VulnerabilityDatabase  (utils.vulnerability_db)
- GitHandler             (utils.git_handler)
- SecurityReportGenerator(utils.pdf_generator)
"""

from .vulnerability_db import VulnerabilityDatabase
from .git_handler import GitHandler
from .pdf_generator import SecurityReportGenerator

__all__ = [
    "VulnerabilityDatabase",
    "GitHandler",
    "SecurityReportGenerator",
]
