from typing import Any, Dict, Optional, List
from report import Reporter, NullReporter
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import requests
import config as cfg
import logging
import sys
from http import HTTPStatus

# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
# enables retry printing
# logging.getLogger("urllib3").setLevel(logging.DEBUG)


AAD_GRAPH_API, MS_GRAPH_API, ARM_API,  = (
    cfg.AAD_GRAPH_API, cfg.MS_GRAPH_API, cfg.ARM_API
)


class BaseClient:
    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        rep: Optional[Reporter] = None,
        session: Optional[requests.Session] = None,
        default_headers: Optional[Dict[str, str]] = None,
        backoff_factor: float = 1.0,
        max_retries: int = 5,
        time_out: float = 15.0
    ):
        # Reporting
        self.rep = rep or NullReporter()

        self.base = base_url.rstrip("/")

        # Header
        headers = (default_headers or {}).copy()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Session
        self.session = session or requests.Session()
        self.session.headers.update(headers)
        self.time_out = time_out
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        retries = Retry(
            total=self.max_retries,
            # backoff time until next try: min(backoff_factor * 2^(n-1), BACKOFF_MAX)
            backoff_factor=self.backoff_factor,
            status_forcelist=[
                HTTPStatus.TOO_MANY_REQUESTS,          # 429
                HTTPStatus.REQUEST_TIMEOUT,            # 408
                HTTPStatus.INTERNAL_SERVER_ERROR,      # 500
                HTTPStatus.BAD_GATEWAY,                # 502
                HTTPStatus.SERVICE_UNAVAILABLE,        # 503
                HTTPStatus.GATEWAY_TIMEOUT,            # 504
            ],
            allowed_methods=frozenset(
                {"HEAD", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
            respect_retry_after_header=True,
        )

        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount(f"{self.base}/", adapter)

    def _abs(self, endpoint: str) -> str:
        return endpoint if endpoint.startswith("http") else f"{self.base}{endpoint}"

    def _request(self, method: str, url: str, *,
                 params: Optional[Dict[str, Any]] = None,
                 json: Optional[Any] = None) -> Optional[Dict[str, Any]]:

        try:
            r = self.session.request(
                method=method,
                url=url,
                params=params,
                # max time for single request
                timeout=self.time_out,
                json=json,
            )
        except requests.RequestException as e:
            self.rep.error(f"Request error {method} {url}: {e}")
            return None

        if not r.ok:
            preview = r.text[:500] if r.text else ""
            self.rep.error(
                f"{r.status_code} {r.reason} for {r.url}\n{preview}")
            return None

        # JSON parse
        try:
            return r.json()
        except ValueError:
            self.rep.error(f"JSON parse error for {r.url}")
            return None

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = endpoint if endpoint.startswith(
            "http") else f"{self.base}{endpoint}"
        return self._request("GET", url, params=params)

    def post(self, endpoint: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = endpoint if endpoint.startswith(
            "http") else f"{self.base}{endpoint}"
        return self._request("POST", url, params=params, json=body)

    def patch(self, endpoint: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = endpoint if endpoint.startswith(
            "http") else f"{self.base}{endpoint}"
        return self._request("PATCH", url, params=params, json=body)

    def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = endpoint if endpoint.startswith(
            "http") else f"{self.base}{endpoint}"
        return self._request("DELETE", url, params=params)

    def get_paged(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[List[Dict[str, Any]]]:
        items: List[Dict[str, Any]] = []
        next_url = self._abs(endpoint)
        q = params or {}
        while next_url:
            try:
                r = self.session.get(next_url, params=q, timeout=self.time_out)
                r.raise_for_status()
            except requests.RequestException as e:
                self.rep.error(f"Paging error GET {next_url}: {e}")
                return None
            data = r.json()
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
            q = {}  # nextLink enthält bereits alle Query-Parameter
        return items


class MSGraphClient(BaseClient):
    def __init__(self, token: str, version: str = "v1.0",
                 rep: Optional[Reporter] = None, session: Optional[requests.Session] = None,
                 **kw):
        super().__init__(base_url=f"{MS_GRAPH_API}/{version}", token=token,
                         rep=rep, session=session, **kw)

    # Helpers
    def get_one(self, endpoint: str, params=None) -> Optional[Dict[str, Any]]:
        return self.get(endpoint, params=params)

    def list(self, endpoint: str, params=None) -> Optional[List[Dict[str, Any]]]:
        return self.get_paged(endpoint, params=params)

    def organization(self):
        data = self.list("/organization")
        return data[0] if data else None

    def users(self, params=None):
        return self.list("/users", params=params)

    def groups(self, params=None):
        return self.list("/groups", params=params)

    def group_settings(self, params=None):
        return self.list("/groupSettings", params=params)

    def service_principals(self, params=None):
        return self.list("/servicePrincipals", params=params)

    def directory_roles(self, expand_members=False):
        p = {"$expand": "members"} if expand_members else None
        return self.list("/directoryRoles", params=p)

    def user_reg_details(self):
        return self.list("/reports/authenticationMethods/userRegistrationDetails")

    def auth_policy(self):
        return self.get_one("/policies/authorizationPolicy/authorizationPolicy")

    def devices(self, params=None):
        return self.list("/devices", params=params)

    def named_locations(self):
        return self.list("/identity/conditionalAccess/namedLocations")


class MSGraphBetaClient(MSGraphClient):
    def __init__(self, token: str, **kw):
        super().__init__(token=token, version="beta", **kw)


class AADGraphClient(BaseClient):
    def __init__(self, tenant_id: str, token: str,
                 api_version: str = "1.61-internal",
                 rep: Optional[Reporter] = None, session: Optional[requests.Session] = None,
                 **kw):
        super().__init__(base_url=f"{AAD_GRAPH_API}/{tenant_id}", token=token,
                         rep=rep, session=session, **kw)
        self.api_version = api_version

    def get(self, endpoint: str, params=None):
        p = (params or {}).copy()
        p["api-version"] = self.api_version
        return super().get(endpoint, params=p)

    def get_paged(self, endpoint: str, params=None):
        p = (params or {}).copy()
        p["api-version"] = self.api_version
        return super().get_paged(endpoint, params=p)

    def list(self, endpoint: str, params=None):
        return self.get_paged(endpoint, params=params)


class ARMClient(BaseClient):
    def __init__(self, token: str, api_version: str = "2018-02-01",
                 rep: Optional[Reporter] = None, session: Optional[requests.Session] = None,
                 **kw):
        super().__init__(base_url=ARM_API, token=token, rep=rep, session=session, **kw)
        self.api_version = api_version

    def get(self, endpoint: str, params=None):
        p = (params or {}).copy()
        p["api-version"] = self.api_version
        return super().get(endpoint, params=p)

    def list(self, endpoint: str, params=None):
        p = (params or {}).copy()
        p["api-version"] = self.api_version
        return super().get_paged(endpoint, params=p)
