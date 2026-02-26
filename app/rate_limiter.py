"""
Rate limiter instance shared across the application.

Separated from main.py to avoid circular imports when used in routers.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
