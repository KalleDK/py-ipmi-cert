from datetime import datetime

from ipmi_cert import BMCResetResponse, BMCResetStateCode, SSLStatus, SSLStatusResponse

REBOOT_RESPONSE = """<?xml version="1.0" ?>
<IPMI>
<BMC_RESET>
<STATE CODE="OK"/>
</BMC_RESET>
</IPMI>"""

SSL_INFO_RESPONSE = '<?xml version="1.0"?>  <IPMI>  <SSL_INFO>  <STATUS VALID_FROM="Jan 28 15:42:21 2025" VALID_UNTIL="Apr 28 15:42:20 2025" CERT_EXIST="01"/>  </SSL_INFO>  </IPMI>'
SSL_INFO_VALID_RESPONSE = """<?xml version="1.0"?>
<IPMI>
  <SSL_INFO VALIDATE="1"/>
</IPMI>"""


def test_bmc_reset():
    got = BMCResetResponse.model_validate_xml(REBOOT_RESPONSE)

    assert got.bmc_reset.state.code == BMCResetStateCode.OK


def test_ssl_status():
    got = SSLStatusResponse.model_validate_xml(SSL_INFO_RESPONSE)

    assert got.ssl_info.status == SSLStatus(
        has_cert=True, valid_from=datetime(2025, 1, 28, 15, 42, 21), valid_until=datetime(2025, 4, 28, 15, 42, 20)
    )


def test_ssl_info():
    got = SSLStatusResponse.model_validate_xml(SSL_INFO_VALID_RESPONSE)

    assert got.ssl_info.validated == 1
