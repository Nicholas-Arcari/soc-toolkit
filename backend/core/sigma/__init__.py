"""Sigma rule engine - generic, SIEM-agnostic detection rules."""
from core.sigma.engine import SigmaEngine, get_engine
from core.sigma.rule import SigmaMatch, SigmaRule

__all__ = ["SigmaEngine", "SigmaMatch", "SigmaRule", "get_engine"]