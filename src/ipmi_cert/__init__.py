import contextlib
import dataclasses
import logging
import pathlib
import re
from datetime import datetime
from typing import Any, Generator, Literal, Mapping, overload

import httpx
import pydantic
import pydantic.fields

from ipmi_cert._types import BMCResetStateCode, Credentials
from ipmi_cert.forms import Form, OperationForm, SSLUploadForm, X11LoginForm
from ipmi_cert.xmlparser import BaseXML

log = logging.getLogger(__name__)

# region Responses


class SSLStatus(BaseXML):
    has_cert: bool = pydantic.Field(validation_alias="CERT_EXIST")
    valid_from: datetime | None
    valid_until: datetime | None

    @pydantic.field_validator("has_cert", mode="before")
    @classmethod
    def _parse_has_cert(cls, value: str):
        return int(value) > 0

    @pydantic.field_validator("valid_from", "valid_until", mode="before")
    @classmethod
    def _parse_datetime(cls, value: str | datetime | None) -> datetime | None:
        if isinstance(value, str):
            return datetime.strptime(value, "%b %d %H:%M:%S %Y")
        return value


class SSLInfo(BaseXML):
    status: SSLStatus | None = None
    validated: int | None = pydantic.Field(default=None, validation_alias="VALIDATE")


class SSLStatusResponse(BaseXML):
    ssl_info: SSLInfo


class BMCResetState(BaseXML):
    code: BMCResetStateCode


class BMCReset(BaseXML):
    state: BMCResetState


class BMCResetResponse(BaseXML):
    bmc_reset: BMCReset


# endregion

# region Config

DOMAIN_RE = re.compile(r"^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$")


@dataclasses.dataclass
class Config:
    ipmi_url: str
    key_file: pathlib.Path
    cert_file: pathlib.Path
    credentials: Credentials
    quiet: bool
    debug: bool
    no_reboot: bool
    no_ssl_check: bool
    base_url: str = dataclasses.field(init=False)

    def __post_init__(self):
        if DOMAIN_RE.match(self.ipmi_url):
            self.base_url = f"https://{self.ipmi_url}"
        elif self.ipmi_url.endswith("/"):
            self.base_url = self.ipmi_url[:-1]
        else:
            self.base_url = self.ipmi_url


# endregion

# region Auth


class IPMIAuth(httpx.Auth):
    requires_response_body = True

    def __init__(self, credentials: Credentials):
        self._credentials = credentials
        self._csrf_token: str | None = None
        self._client: httpx.Client | httpx.AsyncClient | None = None

    @property
    def csrf_token(self) -> str:
        if self._csrf_token is None:
            raise Exception("csrf token not set")
        return self._csrf_token

    @property
    def client(self) -> httpx.Client | httpx.AsyncClient:
        if self._client is None:
            raise Exception("client not set")
        return self._client

    @client.setter
    def client(self, value: httpx.Client | httpx.AsyncClient):
        self._client = value

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self._csrf_token is None:
            response = yield self.client.build_request(
                "POST", "cgi/login.cgi", data=X11LoginForm.create(self._credentials).data
            )
            response.raise_for_status()

            response = yield self.client.build_request("GET", "/cgi/url_redirect.cgi?url_name=topmenu")
            response.raise_for_status()

            self._csrf_token = self._get_csrf_token(response)

        self.client.cookies.set_cookie_header(request)

        if request.url.path.endswith("/cgi/ipmi.cgi"):
            request.headers["CSRF_TOKEN"] = self._csrf_token
            request.headers["X-Requested-With"] = "XMLHttpRequest"
            yield request

        elif request.url.path.endswith("/cgi/op.cgi"):
            request.headers["CSRF_TOKEN"] = self._csrf_token
            request.headers["X-Requested-With"] = "XMLHttpRequest"
            yield request

        else:
            response = yield request
            self._csrf_token = self._get_csrf_token(response)

    def _get_csrf_token(self, resp: httpx.Response) -> str:
        match = re.search(r'SmcCsrfInsert\s*\("CSRF_TOKEN"\s*,\s*"([^"]+)"\);', resp.text)
        if not match:
            raise Exception("can't find csrf token")

        return match.group(1)


# endregion


@dataclasses.dataclass(slots=True)
class IPMIApi:
    transport: httpx.AsyncClient
    auth: IPMIAuth

    @classmethod
    @contextlib.asynccontextmanager
    async def session(cls, config: Config):
        auth = IPMIAuth(config.credentials)
        client = httpx.AsyncClient(base_url=config.base_url, auth=auth, verify=(not config.no_ssl_check))
        auth.client = client
        api = IPMIApi(
            client,
            auth,
        )
        try:
            yield api
        finally:
            pass

    async def _get(self, url: str, headers: Mapping[str, Any] | None = None):
        result = (await self.transport.get(url, headers=headers)).raise_for_status()

        return result.text

    async def _post(self, url: str, *, headers: Mapping[str, Any] | None = None, form: Form | None = None):
        result = (
            await self.transport.post(
                url,
                data=None if form is None else form.data,
                files=None if form is None else form.files,
                headers=headers,
            )
        ).raise_for_status()

        return result.text

    async def _do_op[T: BaseXML](self, cls: type[T], form: OperationForm) -> T:
        resp = await self._post("/cgi/op.cgi", form=form)
        return cls.model_validate_xml(resp)

    async def _do_ipmi_op[T: BaseXML](self, cls: type[T], form: OperationForm) -> T:
        log.debug("doing ipmi op %s", form.op)
        resp = await self._post("/cgi/ipmi.cgi", form=form)
        log.debug("got response %s", resp)
        return cls.model_validate_xml(resp)

    async def get_cert_status(self) -> SSLStatus:
        resp = await self._do_ipmi_op(SSLStatusResponse, OperationForm("SSL_STATUS.XML", "(0,0)"))

        if resp.ssl_info.status is None:
            raise Exception("cant find ssl status")

        return resp.ssl_info.status

    async def validate_uploaded_cert(self):
        resp = await self._do_ipmi_op(SSLStatusResponse, OperationForm("SSL_VALIDATE.XML", "(0,0)"))
        if resp.ssl_info.validated is None:
            raise Exception("cant find ssl validation")

        return resp.ssl_info.validated == 1

    @overload
    async def upload_cert(
        self, cert: bytes | pathlib.Path, key: bytes | pathlib.Path, validate: Literal[True] = ...
    ) -> bool: ...

    @overload
    async def upload_cert(
        self, cert: bytes | pathlib.Path, key: bytes | pathlib.Path, validate: Literal[False]
    ) -> None: ...

    @overload
    async def upload_cert(
        self, cert: bytes | pathlib.Path, key: bytes | pathlib.Path, validate: bool
    ) -> bool | None: ...

    async def upload_cert(
        self, cert: bytes | pathlib.Path, key: bytes | pathlib.Path, validate: bool = True
    ) -> bool | None:
        if isinstance(cert, pathlib.Path):
            cert = cert.read_bytes()
        if isinstance(key, pathlib.Path):
            key = key.read_bytes()
        await self._post("/cgi/upload_ssl.cgi", form=SSLUploadForm.from_bytes(self.auth.csrf_token, cert, key))

        if validate:
            return await self.validate_uploaded_cert()

    async def reboot(self):
        resp = await self._do_op(BMCResetResponse, OperationForm("main_bmcreset"))

        return resp.bmc_reset.state.code == BMCResetStateCode.OK
