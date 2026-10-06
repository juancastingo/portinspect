"""portinspect - Lightweight Python library and CLI for inspecting local network listening ports."""

from .models import ListeningSocket, InspectionReport
from .scanner import get_listening_sockets, inspect_exposure

__version__ = "0.1.0"
__all__ = [
    "ListeningSocket",
    "InspectionReport",
    "get_listening_sockets",
    "inspect_exposure",
]
