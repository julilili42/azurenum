from enum import Enum

class AuthFlow(str, Enum):
    DEVICE_CODE = "DEVICE_CODE_FLOW"
    ROPC        = "ROPC_FLOW"
    REFRESH     = "REFRESH_TOKEN_FLOW"

__all__ = ["AuthFlow"]
