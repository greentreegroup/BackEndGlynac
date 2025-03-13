"""
Common documentation package.
This package provides base API documentation and common models.
"""

from .base import api, auth_ns, user_ns, health_ns

__all__ = [
    'api',
    'user_ns',
    'health_ns',
    'auth_ns'
] 