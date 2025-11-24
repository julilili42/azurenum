from typing import Final, Tuple

AUTHORITY_URL: Final[str] = "https://login.microsoftonline.com/"

# Authentication GUIDs and constants
SCOPE_MS_GRAPH: Final[Tuple[str, ...]] = ("https://graph.microsoft.com/.default",)
SCOPE_AAD_GRAPH: Final[Tuple[str, ...]] = ("https://graph.windows.net/.default",)
SCOPE_ARM:      Final[Tuple[str, ...]] = ("https://management.core.windows.net/.default",)
SCOPE_MSPIM:    Final[Tuple[str, ...]] = ("01fc33a7-78ba-4d2f-a4b7-768e336e890e/.default",)

OFFICE_CLIENT_ID:   Final[str] = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AZURECLI_CLIENT_ID: Final[str] = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
MANAGED_MEETING_ROOMS_CLIENT_ID: Final[str] = "eb20f3e3-3dce-4d2c-b721-ebb8d4414067"

#POWER_AUTOMATE_CLIENT_ID = "386ce8c0-7421-48c9-a1df-2a532400339f" # not foci
# FOCI clients see https://github.com/dirkjanm/family-of-client-ids-research/blob/main/known-foci-clients.csv

__all__ = [
    "AUTHORITY_URL","SCOPE_MS_GRAPH","SCOPE_AAD_GRAPH","SCOPE_ARM","SCOPE_MSPIM",
    "OFFICE_CLIENT_ID","AZURECLI_CLIENT_ID","MANAGED_MEETING_ROOMS_CLIENT_ID",
]
