import pytest

from ioc_enrich.detect import detect_ioc
from ioc_enrich.models import IOCType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IOCType.IP),
        ("2001:db8::1", IOCType.IP),
        ("example.com", IOCType.DOMAIN),
        ("sub.domain.example.co.uk", IOCType.DOMAIN),
        ("https://example.com/path?q=1", IOCType.URL),
        ("http://8.8.8.8/x", IOCType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.HASH),  # MD5
        ("3395856ce81f2b7382dee72602f798b642f14140", IOCType.HASH),  # SHA1
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IOCType.HASH,
        ),  # SHA256
    ],
)
def test_detects_type(value, expected):
    assert detect_ioc(value).type is expected


def test_hash_and_domain_lowercased():
    assert detect_ioc("44D88612FEA8A8F36DE82E1278ABB02F").value == (
        "44d88612fea8a8f36de82e1278abb02f"
    )
    assert detect_ioc("EXAMPLE.COM").value == "example.com"


@pytest.mark.parametrize("value", ["", "   ", "not an ioc!!", "999.999.1.1", "hola"])
def test_rejects_garbage(value):
    with pytest.raises(ValueError):
        detect_ioc(value)
