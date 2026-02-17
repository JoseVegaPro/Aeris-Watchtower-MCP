import base64
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import yaml
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.responses import PlainTextResponse

OPENAPI_FILE = os.getenv("AERISWT_OPENAPI_FILE", "/app/watchtower-api-openapi.yaml")
DEFAULT_BASE_URL = "https://watchtower-api-prd.aeriscloud.com"
TOKEN_PATH = "/watchtower/v1/auth/token"
REQUEST_TIMEOUT = float(os.getenv("AERISWT_TIMEOUT_SECONDS", "30"))
TOKEN_REFRESH_SKEW_SECONDS = 30


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


MCP_BEARER_TOKEN = _require_env("MCP_BEARER_TOKEN")
AERISWT_CLIENT_ID = _require_env("AERISWT_CLIENT_ID")
AERISWT_CLIENT_SECRET = _require_env("AERISWT_CLIENT_SECRET")
AERISWT_BASE_URL = os.getenv("AERISWT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


@dataclass(frozen=True)
class OperationMeta:
    operation_id: str
    method: str
    path: str
    summary: str
    description: str
    requires_account_id: bool
    required_path_params: tuple[str, ...]
    has_body: bool


class TokenManager:
    def __init__(self, base_url: str, client_id: str, client_secret: str) -> None:
        self._base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._expires_at: float = 0
        self._lock = threading.Lock()

    def _fetch_token(self) -> tuple[str, float]:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{self._base_url}{TOKEN_PATH}",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        if resp.status_code in (400, 401):
            raise RuntimeError(
                "AerisWT token request failed. Check AERISWT_CLIENT_ID and "
                "AERISWT_CLIENT_SECRET."
            )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("AerisWT token response missing access_token.")
        expires_in = int(data.get("expires_in", 300))
        expires_at = time.time() + max(30, expires_in - TOKEN_REFRESH_SKEW_SECONDS)
        return token, expires_at

    def get_access_token(self) -> str:
        now = time.time()
        with self._lock:
            if self._token and now < self._expires_at:
                return self._token
            token, expires_at = self._fetch_token()
            self._token = token
            self._expires_at = expires_at
            return token


def _load_openapi(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolve_parameter(
    parameter: dict[str, Any], components: dict[str, Any]
) -> dict[str, Any]:
    ref = parameter.get("$ref")
    if not ref:
        return parameter
    if not ref.startswith("#/components/parameters/"):
        raise RuntimeError(f"Unsupported parameter reference: {ref}")
    key = ref.rsplit("/", 1)[-1]
    resolved = components.get("parameters", {}).get(key)
    if not resolved:
        raise RuntimeError(f"Could not resolve parameter reference: {ref}")
    return resolved


def _build_operations(spec: dict[str, Any]) -> list[OperationMeta]:
    components = spec.get("components", {})
    paths = spec.get("paths", {})
    operations: list[OperationMeta] = []

    for path, path_item in paths.items():
        path_level_parameters = path_item.get("parameters", [])
        for method, op in path_item.items():
            m = method.lower()
            if m not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation_id = op.get("operationId")
            if not operation_id:
                continue
            if operation_id == "getToken":
                continue

            op_tags = op.get("tags", [])
            if "Token" in op_tags:
                continue

            combined_params = list(path_level_parameters) + list(op.get("parameters", []))
            resolved_params = [
                _resolve_parameter(param, components) for param in combined_params
            ]

            required_path_params: list[str] = []
            requires_account_id = False
            for param in resolved_params:
                name = param.get("name", "")
                location = param.get("in", "")
                required = bool(param.get("required", False))
                if location == "path" and required:
                    required_path_params.append(name)
                if name == "X-Watchtower-Account-Id":
                    requires_account_id = True

            operations.append(
                OperationMeta(
                    operation_id=operation_id,
                    method=m.upper(),
                    path=path,
                    summary=(op.get("summary") or "").strip(),
                    description=(op.get("description") or "").strip(),
                    requires_account_id=requires_account_id,
                    required_path_params=tuple(required_path_params),
                    has_body="requestBody" in op,
                )
            )
    return operations


def _render_path(path_template: str, path_params: dict[str, Any]) -> str:
    missing: list[str] = []
    result = path_template
    for name in re.findall(r"{([^}]+)}", path_template):
        if name not in path_params:
            missing.append(name)
            continue
        value = quote(str(path_params[name]), safe="")
        result = result.replace("{" + name + "}", value)
    if missing:
        raise ValueError(
            f"Missing required path parameters: {', '.join(sorted(set(missing)))}"
        )
    return result


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


def _format_upstream_error(resp: httpx.Response, operation_id: str) -> str:
    data = _safe_json(resp)
    detail = ""
    trace_id = None

    if isinstance(data, dict):
        for key in ("message", "error_description", "error", "detail", "title"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                detail = value.strip()
                break
        trace_id_value = data.get("traceId") or data.get("trace_id")
        if isinstance(trace_id_value, str) and trace_id_value.strip():
            trace_id = trace_id_value.strip()
    elif isinstance(data, list):
        detail = "Upstream returned a list error payload."

    if not detail:
        text = resp.text.strip()
        if text:
            detail = text[:400]

    message = f"AerisWT API error {resp.status_code} on {operation_id}"
    if detail:
        message = f"{message}: {detail}"
    if resp.status_code == 401:
        message = (
            f"{message}. Verify AERISWT_CLIENT_ID/AERISWT_CLIENT_SECRET and account access."
        )
    elif resp.status_code == 403:
        message = f"{message}. Check provider roles/permissions for this client."
    elif resp.status_code == 413:
        message = (
            f"{message}. Request exceeded retrieval limit; use related /export endpoint "
            "and poll getScheduledReport."
        )
    elif resp.status_code == 429:
        message = (
            f"{message}. Rate limited (10 requests/minute per client_id and accountId). "
            "Retry with backoff."
        )
    if trace_id:
        message = f"{message} (traceId: {trace_id})"
    return message


def _normalize_success(resp: httpx.Response) -> dict[str, Any] | list[Any] | str:
    content_type = (resp.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        return resp.json()
    if content_type.startswith("text/"):
        return resp.text
    return {
        "status_code": resp.status_code,
        "content_type": content_type,
        "content_base64": base64.b64encode(resp.content).decode("ascii"),
    }


class AerisWTClient:
    def __init__(self, base_url: str, token_manager: TokenManager):
        self._base_url = base_url
        self._token_manager = token_manager

    def call(
        self,
        meta: OperationMeta,
        *,
        account_id: int | str | None,
        payload: dict[str, Any] | None,
    ) -> Any:
        payload_obj = payload or {}
        if not isinstance(payload_obj, dict):
            raise ValueError("payload must be an object with path/query/body/headers keys.")

        path_params = payload_obj.get("path", {})
        query_params = payload_obj.get("query", {})
        body = payload_obj.get("body")
        extra_headers = payload_obj.get("headers", {})

        if path_params is None:
            path_params = {}
        if query_params is None:
            query_params = {}
        if extra_headers is None:
            extra_headers = {}

        if not isinstance(path_params, dict):
            raise ValueError("payload.path must be an object")
        if not isinstance(query_params, dict):
            raise ValueError("payload.query must be an object")
        if not isinstance(extra_headers, dict):
            raise ValueError("payload.headers must be an object")

        rendered_path = _render_path(meta.path, path_params)
        headers: dict[str, str] = {str(k): str(v) for k, v in extra_headers.items()}
        headers["Authorization"] = f"Bearer {self._token_manager.get_access_token()}"

        if meta.requires_account_id:
            if account_id is None:
                raise ValueError(
                    "account_id is required for this operation and maps to "
                    "X-Watchtower-Account-Id."
                )
            headers["X-Watchtower-Account-Id"] = str(account_id)

        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "params": query_params,
            "timeout": REQUEST_TIMEOUT,
        }
        if meta.has_body and body is not None:
            request_kwargs["json"] = body

        url = f"{self._base_url}{rendered_path}"
        with httpx.Client() as client:
            resp = client.request(meta.method, url, **request_kwargs)
            if resp.status_code == 401:
                # Retry once after token refresh in case upstream token expired early.
                self._token_manager._expires_at = 0
                headers["Authorization"] = (
                    f"Bearer {self._token_manager.get_access_token()}"
                )
                resp = client.request(meta.method, url, **request_kwargs)

        if resp.is_error:
            raise ValueError(_format_upstream_error(resp, meta.operation_id))
        return _normalize_success(resp)


def _make_tool(meta: OperationMeta, client: AerisWTClient):
    summary = meta.summary or f"{meta.method} {meta.path}"
    requires = "yes" if meta.requires_account_id else "no"

    def _tool(
        account_id: int | str | None = None, payload: dict[str, Any] | None = None
    ) -> Any:
        return client.call(meta, account_id=account_id, payload=payload)

    _tool.__name__ = meta.operation_id
    _tool.__doc__ = (
        f"{summary}\n\n"
        f"method: {meta.method}\n"
        f"path: {meta.path}\n"
        f"requires_account_id: {requires}\n"
        "payload format: {path?: {}, query?: {}, body?: any, headers?: {}}"
    )
    return _tool


spec = _load_openapi(OPENAPI_FILE)
operations = _build_operations(spec)
token_manager = TokenManager(AERISWT_BASE_URL, AERISWT_CLIENT_ID, AERISWT_CLIENT_SECRET)
api_client = AerisWTClient(AERISWT_BASE_URL, token_manager)

mcp = FastMCP(
    "Watchtower MCP",
    auth=StaticTokenVerifier(tokens={MCP_BEARER_TOKEN: {"client_id": "local"}}),
)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Any) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.tool()
def list_watchtower_operations() -> list[dict[str, Any]]:
    """List all generated Watchtower operation-backed MCP tools."""
    return [
        {
            "operation_id": op.operation_id,
            "method": op.method,
            "path": op.path,
            "requires_account_id": op.requires_account_id,
            "has_body": op.has_body,
        }
        for op in operations
    ]


for operation in operations:
    mcp.tool()(_make_tool(operation, api_client))


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=8000,
        path="/mcp",
    )
