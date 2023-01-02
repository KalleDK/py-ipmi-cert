import argparse
import collections.abc
import dataclasses
import logging
import os
import re
import sys
from base64 import b64encode
from datetime import datetime
from typing import Any, Optional, Union, cast

import requests
from dotenv import load_dotenv  # type: ignore
from lxml import etree

log = logging.getLogger(__name__)

Element = Any


@dataclasses.dataclass
class SSLStatus:
    has_cert: bool
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]

    @classmethod
    def from_xml(cls, item: Element):
        return cls(
            has_cert=int(item.get("CERT_EXIST", 0)) > 0,
            valid_from=_parse_opt_datetime(item.get("VALID_FROM")),
            valid_until=_parse_opt_datetime(item.get("VALID_UNTIL")),
        )


@dataclasses.dataclass(slots=True)
class FormFile:
    filename: str
    data: Union[bytes, str]
    content_type: str = "application/octet-stream"

    def as_formdata(self):
        return (self.filename, self.data, self.content_type)


@dataclasses.dataclass(slots=True)
class Form(collections.abc.Mapping[str, Any]):
    def __iter__(self):
        for x in ["data", "files"]:
            yield x

    def __len__(self) -> int:
        return 2

    def __getitem__(self, key: str):
        if key == "files":
            return self._get_files()
        if key == "data":
            return self._get_data()

    def _get_files(self):
        files: list[tuple[str, tuple[str, str | bytes, str]]] = []
        fields = dataclasses.fields(self)
        for field in fields:
            value = getattr(self, field.name)
            if isinstance(value, FormFile):
                key = field.name
                if field.metadata is not None and "key" in field.metadata:
                    key = field.metadata["key"]
                files.append((key, value.as_formdata()))

        if len(files) < 1:
            return None

        return files

    def _get_data(self):
        data: dict[str, Any] = {}
        fields = dataclasses.fields(self)
        for field in fields:
            value = getattr(self, field.name)
            if not isinstance(value, FormFile):
                key = field.name
                if field.metadata is not None and "key" in field.metadata:
                    key = field.metadata["key"]
                data[key] = value

        if len(data) < 1:
            return None

        return data


@dataclasses.dataclass(slots=True)
class SSLUploadForm(Form):
    CSRF_TOKEN: str
    cert_file: FormFile
    key_file: FormFile


@dataclasses.dataclass(slots=True)
class X11LoginForm(Form):
    name: bytes
    pwd: bytes
    check: str


@dataclasses.dataclass(slots=True)
class OperationForm(Form):
    op: str
    r: Optional[str] = None
    underscore: str = dataclasses.field(default="", metadata={"key": "_"})


def _parse_opt_datetime(line: Optional[str]):
    if line is None:
        return None
    return datetime.strptime(line, "%b %d %H:%M:%S %Y")


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


@dataclasses.dataclass(slots=True)
class IPMICertUpdater:
    session: requests.Session
    url: str
    verify: Optional[bool] = None
    timeout: Optional[float] = None
    csfr_token: str = ""

    def _make_redirect_url(self, url_name: str):
        return f"{self.url}/cgi/url_redirect.cgi?url_name={url_name}"

    def _post(self, url: str, headers: dict[str, Any], form: Form):
        result = self.session.post(
            url,
            **form,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify,
        )

        result.raise_for_status()

        return result.text

    def _get(self, url: str, headers: Optional[dict[str, Any]] = None):
        result = self.session.get(
            url,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify,
        )

        result.raise_for_status()

        return result.text

    # region Forms

    def _make_login_form(self, username: str, password: str):
        return X11LoginForm(
            name=b64encode(username.encode("UTF-8")),
            pwd=b64encode(password.encode("UTF-8")),
            check="00",
        )

    def _make_ssl_cert_form(self, cert_data: bytes, key_data: bytes):
        return SSLUploadForm(
            CSRF_TOKEN=self.csfr_token,
            cert_file=FormFile("server_cert.pem", cert_data),
            key_file=FormFile("server_key.pem", key_data),
        )

    # endregion

    def _get_csrf_token(self, url_name: str):
        body = self._get(url=self._make_redirect_url(url_name))

        match = re.search(r'SmcCsrfInsert\s*\("CSRF_TOKEN"\s*,\s*"([^"]+)"\);', body)
        if not match:
            raise Exception("can't find csrf token")

        return cast(str, match.group(1))

    def _make_headers(self, url_name: str):
        return {
            "Origin": self.url,
            "Referer": self._make_redirect_url(url_name),
        }

    def _make_xhr_headers(self, url_name: str):
        headers = self._make_headers(url_name)
        headers["CSRF_TOKEN"] = self.csfr_token
        headers["X-Requested-With"] = "XMLHttpRequest"
        return headers

    def _do_op(self, form: OperationForm):
        body = self._post(
            f"{self.url}/cgi/op.cgi",
            headers=self._make_xhr_headers("mainmenu"),
            form=form,
        )

        return etree.fromstring(body)

    def _do_ipmi_op(self, form: OperationForm):
        body = self._post(
            f"{self.url}/cgi/ipmi.cgi",
            headers=self._make_xhr_headers("mainmenu"),
            form=form,
        )

        log.debug(body)

        return etree.fromstring(body)

    def login(self, username: str, password: str):
        """
        Log into IPMI interface
        :param username: username to use for logging in
        :param password: password to use for logging in
        :return: bool
        """
        self._post(
            f"{self.url}/cgi/login.cgi",
            headers={},
            form=self._make_login_form(username, password),
        )

        self.csfr_token = self._get_csrf_token("topmenu")

        return True

    def get_cert_valid(self):
        """
        Verify existing certificate information
        :return: bool
        """
        root = self._do_ipmi_op(OperationForm("SSL_VALIDATE.XML", "(0,0)"))

        # <?xml> <IPMI> <SSL_INFO>
        status = root.find("SSL_INFO")
        if status is None:
            return False

        return int(status.get("VALIDATE", 0)) == 1

    def get_cert_status(self):
        """
        Verify existing certificate information
        :return: dict
        """

        root = self._do_ipmi_op(OperationForm("SSL_STATUS.XML", "(0,0)"))

        # <?xml> <IPMI> <SSL_INFO> <STATUS>
        status = root.find("SSL_INFO/STATUS")
        if status is None:
            raise Exception("cant find ssl status")

        return SSLStatus.from_xml(status)

    def reboot(self):
        root = self._do_op(OperationForm("main_bmcreset"))
        status = root.find("BMC_RESET/STATE")
        if status is None:
            raise Exception("cant find reset status")

        log.debug(status.get("CODE"))

        return status.get("CODE", "").upper() == "OK"

    def upload_cert(self, key: bytes, cert: bytes):
        """
        Send X.509 certificate and private key to server
        :param session: Current session object
        :type session requests.session
        :param url: base-URL to IPMI
        :param key_file: filename to X.509 certificate private key
        :param cert_file: filename to X.509 certificate PEM
        :return:
        """

        # extract certificates only (IPMI doesn't like DH PARAMS)
        cert = _clean_cert_data(cert)

        self._post(
            f"{self.url}/cgi/upload_ssl.cgi",
            form=self._make_ssl_cert_form(cert, key),
            headers=self._make_headers("config_ssl"),
        )

        return self.get_cert_valid()


@dataclasses.dataclass
class ArgsDict:
    ipmi_url: str
    key_file: str
    cert_file: str
    username: str
    password: str
    quiet: bool = False
    debug: bool = False
    no_reboot: bool = False
    no_ssl_check: bool = False


def get_args():

    if len(sys.argv) == 2 and sys.argv[1] == "lego":
        domain = os.environ["LEGO_CERT_DOMAIN"]
        load_dotenv(f"/etc/ipmi_cert/{domain}.env")
        return ArgsDict(
            ipmi_url=os.getenv("IPMI_HOST", f"https://{domain}"),
            username=os.environ["IPMI_USER"],
            password=os.environ["IPMI_PASS"],
            cert_file=os.environ["LEGO_CERT_PATH"],
            key_file=os.environ["LEGO_CERT_KEY_PATH"],
            no_ssl_check=True,
        )

    if len(sys.argv) == 2 and sys.argv[1] == "acme":
        domain = os.environ["Le_Domain"]
        load_dotenv(f"/etc/ipmi_cert/{domain}.env")
        return ArgsDict(
            ipmi_url=os.getenv("IPMI_HOST", f"https://{domain}"),
            username=os.environ["IPMI_USER"],
            password=os.environ["IPMI_PASS"],
            cert_file=os.environ["CERT_FULLCHAIN_PATH"],
            key_file=os.environ["CERT_KEY_PATH"],
            no_ssl_check=True,
        )

    parser = argparse.ArgumentParser(
        description="Update Supermicro IPMI SSL certificate"
    )
    parser.add_argument(
        "-i", "--ipmi-url", required=True, help="Supermicro IPMI 2.0 URL"
    )
    parser.add_argument(
        "-k", "--key-file", required=True, help="X.509 Private key filename"
    )
    parser.add_argument(
        "-c", "--cert-file", required=True, help="X.509 Certificate filename"
    )
    parser.add_argument(
        "-u", "--username", required=True, help="IPMI username with admin access"
    )
    parser.add_argument("-p", "--password", required=True, help="IPMI user password")
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="The default is to reboot the IPMI after upload for the change to take effect.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not output anything if successful",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug",
    )
    parser.add_argument(
        "--no-ssl-check",
        action="store_true",
        help="Ignore ssl cert",
    )
    args: ArgsDict = cast(ArgsDict, parser.parse_args())
    return args


def main():
    args = get_args()

    # Confirm args
    if not os.path.isfile(args.key_file):
        print(f"--key-file '{args.key_file}' doesn't exist!")
        exit(2)
    if not os.path.isfile(args.cert_file):
        print(f"--cert-file '{args.cert_file}' doesn't exist!")
        exit(2)
    if args.ipmi_url[-1] == "/":
        args.ipmi_url = args.ipmi_url[0:-1]

    if not args.quiet:
        level = logging.INFO
        if args.debug:
            level = logging.DEBUG
        logging.basicConfig(level=level)
        # requests_log = logging.getLogger("requests.packages.urllib3")
        # requests_log.setLevel(logging.INFO)

    # Start the operation
    if args.no_ssl_check:
        InsecureRequestWarning = requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore

    updater = IPMICertUpdater(
        session=requests.session(), url=args.ipmi_url, verify=(not args.no_ssl_check)
    )

    if not updater.login(args.username, args.password):
        print("Login failed. Cannot continue!")
        exit(2)

    cert_info = updater.get_cert_status()
    if not cert_info:
        print("Failed to extract certificate information from IPMI!")
        exit(2)
    if not args.quiet and cert_info.has_cert:
        print(
            f"There exists a certificate, which is valid until: {cert_info.valid_until}"
        )

    # Go upload!
    with open(args.cert_file, "rb") as fp:
        cert = fp.read()
    with open(args.key_file, "rb") as fp:
        key = fp.read()
    if not updater.upload_cert(key, cert):
        print("Failed to upload X.509 files to IPMI!")
        exit(2)

    if not args.quiet:
        print("Uploaded files ok.")

    cert_info = updater.get_cert_status()
    if not cert_info:
        print("Failed to extract certificate information from IPMI!")
        exit(2)

    if not args.quiet and cert_info.has_cert:
        print(
            f"After upload, there exists a certificate, which is valid until: {cert_info.valid_until}"
        )

    if not args.no_reboot:
        if not args.quiet:
            print("Rebooting IPMI to apply changes.")
        if not updater.reboot():
            print("Rebooting failed! Go reboot it manually?")

    if not args.quiet:
        print("All done!")


if __name__ == "__main__":
    main()
