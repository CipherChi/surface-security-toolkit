"""Shared in-memory API rate limiting configuration."""

from slowapi import Limiter
from slowapi.util import get_remote_address

# A dashboard run makes several requests, so this allows a small number of
# complete domain or email runs per client each minute.
limiter = Limiter(key_func=get_remote_address)
domain_check_limit = limiter.shared_limit("10/minute", scope="domain-checks")
