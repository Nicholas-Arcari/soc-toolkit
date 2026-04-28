"""Sigma rule engine - generic, SIEM-agnostic detection rules."""
from core.sigma.compiler import SUPPORTED_BACKENDS, compile_rule
from core.sigma.engine import SigmaEngine, get_engine
from core.sigma.rule import SigmaMatch, SigmaRule

__all__ = [
    "SUPPORTED_BACKENDS",
    "SigmaEngine",
    "SigmaMatch",
    "SigmaRule",
    "compile_rule",
    "get_engine",
]
