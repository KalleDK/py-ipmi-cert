import abc
import base64
import dataclasses
import pathlib
import re
from typing import Any, Mapping, Self, override

from ipmi_cert._types import Credentials, FileDataType


def encode_b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("utf-8")


class FormFile:
    @abc.abstractmethod
    def as_formdata(self) -> FileDataType:
        raise NotImplementedError


@dataclasses.dataclass(slots=True)
class BinaryFormFile(FormFile):
    filename: str
    data: bytes
    content_type: str = "application/octet-stream"

    @override
    def as_formdata(self) -> FileDataType:
        return (self.filename, self.data, self.content_type)

    @classmethod
    def from_file(cls, filename: str, file_path: pathlib.Path) -> Self:
        with open(file_path, "rb") as file:
            data = file.read()
        return cls(filename, data)


@dataclasses.dataclass(slots=True)
class Form:
    def _get_data(self) -> None | Mapping[str, Any]:
        data: dict[str, Any] = {}
        fields = dataclasses.fields(self)
        for field in fields:
            value = getattr(self, field.name)
            if not isinstance(value, FormFile):
                key = field.name
                if field.metadata is not None and "key" in field.metadata:
                    key = field.metadata["key"]
                data[key] = value

        return data if data else None

    def _get_files(self) -> None | Mapping[str, FileDataType]:
        files: dict[str, FileDataType] = {}
        fields = dataclasses.fields(self)
        for field in fields:
            value = getattr(self, field.name)
            if isinstance(value, FormFile):
                key = field.name
                if field.metadata is not None and "key" in field.metadata:
                    key = field.metadata["key"]
                files[key] = value.as_formdata()

        return files if files else None

    @property
    def data(self) -> None | Mapping[str, Any]:
        return self._get_data()

    @property
    def files(self) -> None | Mapping[str, FileDataType]:
        return self._get_files()


@dataclasses.dataclass(slots=True)
class SSLUploadForm(Form):
    CSRF_TOKEN: str
    cert_file: FormFile
    key_file: FormFile

    @staticmethod
    def _clean_cert_data(data: bytes):
        return (
            b"\n".join(
                re.findall(
                    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                    data,
                    re.DOTALL,
                )
            )
            + b"\n"
        )

    @classmethod
    def from_files(cls, csrf_token: str, cert_path: pathlib.Path, key_path: pathlib.Path) -> Self:
        return cls.from_bytes(csrf_token, cert_path.read_bytes(), key_path.read_bytes())

    @classmethod
    def from_bytes(cls, csrf_token: str, cert: bytes, key: bytes) -> Self:
        return cls(
            csrf_token,
            BinaryFormFile("server_cert.pem", cls._clean_cert_data(cert)),
            BinaryFormFile("server_key.pem", key),
        )


@dataclasses.dataclass(slots=True)
class X11LoginForm(Form):
    name: str
    pwd: str
    check: str = "00"

    @classmethod
    def create(cls, credentials: Credentials):
        return cls(
            name=encode_b64(credentials.username),
            pwd=encode_b64(credentials.password.get_secret_value()),
        )


@dataclasses.dataclass(slots=True)
class OperationForm(Form):
    op: str
    r: str | None = None
    underscore: str = dataclasses.field(default="", metadata={"key": "_"})
