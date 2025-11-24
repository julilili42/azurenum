from typing import Final, Dict

# Default User-Agent Edge on Windows 10
DEFAULT_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.112"
)

def default_headers() -> Dict[str, str]:
    return {"User-Agent": DEFAULT_USER_AGENT}

__all__ = ["DEFAULT_USER_AGENT", "default_headers"]
