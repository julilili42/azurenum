from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, List
import msal
import os
import config as cfg
from report import Reporter
from enum import Enum


@dataclass
class AuthConfig:
    tenant_id: Optional[str] = None
    authority_base: str = cfg.AUTHORITY_URL  # "https://login.microsoftonline.com/"
    # persitant token saved at cache_path
    cache_path: Optional[str] = None


class Resource(Enum):
    GRAPH = "graph"
    ARM = "arm"
    AAD_GRAPH = "aad_graph"
    CUSTOM = "custom"


class CredentialType(str, Enum):
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"


class AuthError(Exception):
    pass


MFA_REQUIRED = "AADSTS50076"


def _as_scopes_list(scopes):
    if scopes is None:
        return None
    if isinstance(scopes, str):
        return [scopes]
    return list(scopes)


class AuthManager:
    def __init__(self, *, tenant_id: Optional[str], session, cache_path: Optional[str] = None):
        self.config = AuthConfig(tenant_id=tenant_id, cache_path=cache_path)
        self.session = session
        # persistant cache, token is saved and can be used for authentication
        self.cache = msal.SerializableTokenCache()
        if cache_path and os.path.exists(cache_path):
            self.cache.deserialize(open(cache_path, "r").read())
        # temporary cache for single process in ram
        self._last_tokens: Dict[str, dict] = {}
        # app_by_client enables authenticating for multiple clients
        self.app_by_client: Dict[str, msal.PublicClientApplication] = {}
        self.bootstrap_done = False

    def _authority(self) -> str:
        tenant = self.config.tenant_id or "common"
        return f"{self.config.authority_base}{tenant}"

    def _app(self, client_id: str) -> msal.PublicClientApplication:
        app = self.app_by_client.get(client_id)
        if app:
            return app
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=self._authority(),
            token_cache=self.cache,
            http_client=self.session,
        )
        self.app_by_client[client_id] = app
        return app

    def _save_cache(self):
        if self.config.cache_path:
            with open(self.config.cache_path, "w") as f:
                f.write(self.cache.serialize())

    def bootstrap(self, *, client_id: str, scopes: List[str], rep: Reporter,
                  # device code flow
                  device_code: bool = True,
                  username: Optional[str] = None,
                  password: Optional[str] = None) -> dict:
        app = self._app(client_id)
        result = None

        accounts = app.get_accounts()
        scopes = _as_scopes_list(scopes)

        # skips authentication if account previously authenticated
        if accounts:
            result = app.acquire_token_silent(scopes, account=accounts[0])

        if not result:
            if username and password:
                # cli authentication
                result = app.acquire_token_by_username_password(
                    username, password, scopes=scopes)
            elif device_code:
                flow = app.initiate_device_flow(scopes=scopes)
                rep.info(flow.get("message", "Complete device login..."))
                result = app.acquire_token_by_device_flow(flow)
            else:
                raise AuthError("No auth flow configured")

        if not result or not result.get(CredentialType.ACCESS_TOKEN.value):
            err = result or {}
            code = err.get("error")
            desc = err.get("error_description", "")
            if MFA_REQUIRED in desc:
                rep.error("MFA required for this client/resource.")
            raise AuthError(f"Auth failed: {code}: {desc}")

        self.bootstrap_done = True
        self._save_cache()
        self._last_tokens[client_id] = result
        return result

    def token_for(self, resource: Resource, *, rep: Reporter, client_id: Optional[str] = None, scopes: Optional[List[str]] = None) -> str:

        assert self.bootstrap_done, "Call bootstrap() first"

        if scopes is None:
            if resource == Resource.GRAPH:
                scopes = cfg.SCOPE_MS_GRAPH
            elif resource == Resource.ARM:
                scopes = cfg.SCOPE_ARM
            elif resource == Resource.AAD_GRAPH:
                scopes = cfg.SCOPE_AAD_GRAPH
            elif resource == Resource.CUSTOM:
                raise ValueError("Custom resource requires explicit scopes")
            else:
                raise ValueError(f"Unknown resource: {resource}")

        cid = client_id or cfg.AZURECLI_CLIENT_ID
        app = self._app(cid)

        scopes = _as_scopes_list(scopes)

        # silent first
        accounts = app.get_accounts()
        result = app.acquire_token_silent(
            scopes, account=accounts[0] if accounts else None)
        if not result:
            if cid in self._last_tokens and CredentialType.REFRESH_TOKEN.value in self._last_tokens[cid]:
                pass

            flow = app.initiate_device_flow(scopes=scopes)
            rep.info(flow.get("message", "Complete device login..."))
            result = app.acquire_token_by_device_flow(flow)

        if not result or not result.get(CredentialType.ACCESS_TOKEN.value):
            err = result or {}
            raise AuthError(
                f"Token for {resource} failed: {err.get('error_description','')}")

        self._save_cache()
        return result[CredentialType.ACCESS_TOKEN.value]
