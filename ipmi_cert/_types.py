import dataclasses
from enum import StrEnum

from secretstr import SecretStr


@dataclasses.dataclass
class Credentials:
    username: str
    password: SecretStr


FileDataType = tuple[str, str | bytes, str]


class BMCResetStateCode(StrEnum):
    OK = "OK"
