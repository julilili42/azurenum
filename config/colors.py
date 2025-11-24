from typing import Final

# Set colors
RED: Final[str]    = "\033[0;31m"
GREEN: Final[str]  = "\033[0;32m"
YELLOW: Final[str] = "\033[0;33m"
CYAN: Final[str]   = "\033[0;36m"
ORANGE: Final[str] = "\033[38;5;208m"
NC: Final[str]     = "\033[0m"  # No Color

__all__ = ["RED","GREEN","YELLOW","CYAN","ORANGE","NC"]
