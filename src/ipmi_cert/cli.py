import asyncio
import logging
import pathlib
from typing import Annotated

import dotenv
import typer
from secretstr import SecretStr

from ipmi_cert import Config, Credentials, IPMIApi

app = typer.Typer()


def secret_str_parser(value: str) -> SecretStr:
    return SecretStr(value)


async def upload_certificate(config: Config):
    if config.debug:
        logging.basicConfig(level=logging.DEBUG)

    async with IPMIApi.session(config) as api:
        print(await api.get_cert_status())
        print(await api.upload_cert(config.cert_file, config.key_file))
        print(await api.get_cert_status())
        if not config.no_reboot:
            await api.reboot()


@app.command()
def lego(
    ipmi_url: Annotated[
        str, typer.Option("--ipmi-url", "-i", envvar="LEGO_CERT_DOMAIN", help="URL of the IPMI server")
    ],
    username: Annotated[
        str, typer.Option("--username", "-u", envvar="IPMI_USERNAME", help="Username for the IPMI server")
    ],
    password: Annotated[
        SecretStr,
        typer.Option(
            "--password", "-p", envvar="IPMI_PASSWORD", help="Password for the IPMI server", parser=secret_str_parser
        ),
    ],
    cert_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--cert-file",
            "-c",
            envvar="LEGO_CERT_PATH",
            help="Path to the X.509 Certificate file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    key_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--key-file",
            "-k",
            envvar="LEGO_CERT_KEY_PATH",
            help="Path to the X.509 Private key file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    no_reboot: Annotated[
        bool, typer.Option("--no-reboot", help="Do not reboot the server after uploading the certificate")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Do not output anything")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Enable debug mode")] = True,
    no_ssl_check: Annotated[bool, typer.Option("--no-ssl-check", help="Disable SSL certificate verification")] = True,
):
    config = Config(
        ipmi_url=ipmi_url,
        credentials=Credentials(username=username, password=password),
        cert_file=cert_file,
        key_file=key_file,
        no_reboot=no_reboot,
        quiet=quiet,
        debug=debug,
        no_ssl_check=no_ssl_check,
    )
    asyncio.run(upload_certificate(config))


@app.command()
def acme(
    ipmi_url: Annotated[str, typer.Option("--ipmi-url", "-i", envvar="Le_Domain", help="URL of the IPMI server")],
    username: Annotated[
        str, typer.Option("--username", "-u", envvar="IPMI_USERNAME", help="Username for the IPMI server")
    ],
    password: Annotated[
        SecretStr,
        typer.Option(
            "--password", "-p", envvar="IPMI_PASSWORD", help="Password for the IPMI server", parser=secret_str_parser
        ),
    ],
    cert_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--cert-file",
            "-c",
            envvar="CERT_FULLCHAIN_PATH",
            help="Path to the X.509 Certificate file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    key_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--key-file",
            "-k",
            envvar="CERT_KEY_PATH",
            help="Path to the X.509 Private key file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    no_reboot: Annotated[
        bool, typer.Option("--no-reboot", help="Do not reboot the server after uploading the certificate")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Do not output anything")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Enable debug mode")] = False,
    no_ssl_check: Annotated[bool, typer.Option("--no-ssl-check", help="Disable SSL certificate verification")] = True,
):
    config = Config(
        ipmi_url=ipmi_url,
        credentials=Credentials(username=username, password=password),
        cert_file=cert_file,
        key_file=key_file,
        no_reboot=no_reboot,
        quiet=quiet,
        debug=debug,
        no_ssl_check=no_ssl_check,
    )
    asyncio.run(upload_certificate(config))


@app.command()
def upload(
    ipmi_url: Annotated[str, typer.Option("--ipmi-url", "-i", envvar="IPMI_URL", help="URL of the IPMI server")],
    username: Annotated[
        str, typer.Option("--username", "-u", envvar="IPMI_USERNAME", help="Username for the IPMI server")
    ],
    password: Annotated[
        SecretStr,
        typer.Option(
            "--password", "-p", envvar="IPMI_PASSWORD", help="Password for the IPMI server", parser=secret_str_parser
        ),
    ],
    cert_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--cert-file",
            "-c",
            envvar="IPMI_CERT",
            help="Path to the X.509 Certificate file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    key_file: Annotated[
        pathlib.Path,
        typer.Option(
            "--key-file",
            "-k",
            envvar="IPMI_KEY",
            help="Path to the X.509 Private key file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    no_reboot: Annotated[
        bool, typer.Option("--no-reboot", help="Do not reboot the server after uploading the certificate")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Do not output anything")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Enable debug mode")] = False,
    no_ssl_check: Annotated[bool, typer.Option("--no-ssl-check", help="Disable SSL certificate verification")] = False,
):
    config = Config(
        ipmi_url=ipmi_url,
        credentials=Credentials(username=username, password=password),
        cert_file=cert_file,
        key_file=key_file,
        no_reboot=no_reboot,
        quiet=quiet,
        debug=debug,
        no_ssl_check=no_ssl_check,
    )
    asyncio.run(upload_certificate(config))


def main():
    dotenv.load_dotenv()
    app()


if __name__ == "__main__":
    main()
