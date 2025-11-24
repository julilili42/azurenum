from typing import Final

# Misc Constant GUIDs
AAD_PREMIUM_P2: Final[str] = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
AAD_PREMIUM_P1: Final[str] = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
GROUP_UNIFIED_TEMPLATE_ID: Final[str] = "62375ab9-6b52-47ed-826b-58e47e0e304b"

# Guest Roles
GUEST_ROLE_USER: Final[str] = "a0b1b346-4d3e-4e8b-98f8-753987be4970" # https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0&preserve-view=true
GUEST_ROLE_GUEST: Final[str] = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
GUEST_ROLE_RESTRICTED: Final[str] = "2af84b1e-32c8-42b7-82bc-daa82404023b"

MICROSOFT_SERVICE_TENANT_ID: Final[str] = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

__all__ = [
    "AAD_PREMIUM_P2","AAD_PREMIUM_P1","GROUP_UNIFIED_TEMPLATE_ID",
    "GUEST_ROLE_USER","GUEST_ROLE_GUEST","GUEST_ROLE_RESTRICTED",
    "MICROSOFT_SERVICE_TENANT_ID",
]
