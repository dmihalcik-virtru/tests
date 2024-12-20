import base64
import json
import os
import pathlib
import pytest
import random
import secrets
import string

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pydantic_core import to_jsonable_python
from typing import Any, Literal

import abac
import assertions


FileSize = Literal["small", "large"]


def pytest_addoption(parser: pytest.Parser):
    def split_string(s: str) -> list[str]:
        return s.split()

    parser.addoption(
        "--large",
        action="store_true",
        help="generate a large (greater than 4 GiB) file for testing",
    )
    parser.addoption(
        "--sdks", help="select which sdks to run by default, unless overridden"
    )
    parser.addoption(
        "--sdks-decrypt",
        type=split_string,
        help="select which sdks to run for decrypt only",
    )
    parser.addoption(
        "--sdks-encrypt",
        type=split_string,
        help="select which sdks to run for encrypt only",
    )
    parser.addoption(
        "--containers",
        type=split_string,
        help="which container formats to test",
    )

# function that takes a type of Any that we know is a list[str] and returns a type of list[str]
# This is useful for type checking in the pytest_generate_tests function
def is_list(val: Any) -> list[str]:
    return val


def pytest_generate_tests(metafunc: pytest.Metafunc):
    if "size" in metafunc.fixturenames:
        metafunc.parametrize(
            "size",
            ["large" if metafunc.config.getoption("large") else "small"],
            scope="session",
        )
    if "encrypt_sdk" in metafunc.fixturenames:
        encrypt_sdks: list[str] = ["js", "go", "java"]
        if metafunc.config.getoption("--sdks-encrypt"):
            encrypt_sdks = is_list(metafunc.config.getoption("--sdks-encrypt"))
        elif metafunc.config.getoption("--sdks"):
            encrypt_sdks = is_list(metafunc.config.getoption("--sdks"))
        metafunc.parametrize("encrypt_sdk", encrypt_sdks)
    if "decrypt_sdk" in metafunc.fixturenames:
        decrypt_sdks = ["js", "go", "java"]
        if metafunc.config.getoption("--sdks-decrypt"):
            decrypt_sdks = is_list(metafunc.config.getoption("--sdks-decrypt"))
        elif metafunc.config.getoption("--sdks"):
            decrypt_sdks = is_list(metafunc.config.getoption("--sdks"))
        metafunc.parametrize("decrypt_sdk", decrypt_sdks)
    if "container" in metafunc.fixturenames:
        containers = ["nano", "ztdf", "nano-with-ecdsa"]
        if metafunc.config.getoption("--containers"):
            containers = is_list(metafunc.config.getoption("--containers"))
        metafunc.parametrize("container", containers)


@pytest.fixture(scope="module")
def pt_file(tmp_dir: os.PathLike[str], size: FileSize) -> os.PathLike[str]:
    pt_file = pathlib.Path(tmp_dir, f"test-plain-{size}.txt")
    length = (5 * 2**30) if size == "large" else 128
    with open(pt_file, "w") as f:
        for i in range(0, length, 16):
            f.write("{:15,d}\n".format(i))
    return pt_file


@pytest.fixture(scope="module")
def tmp_dir() -> os.PathLike[str]:
    dname = "tmp/"
    if not os.path.exists(dname):
        os.makedirs(dname)
    return pathlib.Path(dname)


_otdfctl = abac.OpentdfCommandLineTool()


@pytest.fixture(scope="module")
def otdfctl() -> abac.OpentdfCommandLineTool:
    return _otdfctl


@pytest.fixture(scope="module")
def temporary_namespace(otdfctl: abac.OpentdfCommandLineTool) -> abac.Namespace:
    return create_temp_namesapce(otdfctl)


def create_temp_namesapce(otdfctl: abac.OpentdfCommandLineTool) -> abac.Namespace:
    # Create a new attribute in a random namespace
    random_ns = "".join(random.choices(string.ascii_lowercase, k=8)) + ".com"
    ns = otdfctl.namespace_create(random_ns)
    return ns


PLATFORM_DIR = os.getenv("PLATFORM_DIR", "../../platform")


def load_cached_kas_keys() -> abac.PublicKey:
    keyset: list[abac.KasPublicKey] = []
    with open(f"{PLATFORM_DIR}/kas-cert.pem", "r") as rsaFile:
        keyset.append(
            abac.KasPublicKey(
                alg=abac.KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
                kid="r1",
                pem=rsaFile.read(),
            )
        )
    with open(f"{PLATFORM_DIR}/kas-ec-cert.pem", "r") as ecFile:
        keyset.append(
            abac.KasPublicKey(
                alg=abac.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
                kid="e1",
                pem=ecFile.read(),
            )
        )
    return abac.PublicKey(
        cached=abac.KasPublicKeySet(
            keys=keyset,
        )
    )


@pytest.fixture(scope="session")
def kas_url_default() -> str:
    return os.getenv("KASURL", "http://localhost:8080/kas")


@pytest.fixture(scope="session")
def kas_url_value1() -> str:
    return os.getenv("KASURL1", "http://localhost:8181/kas")


@pytest.fixture(scope="session")
def kas_url_value2() -> str:
    return os.getenv("KASURL2", "http://localhost:8282/kas")


@pytest.fixture(scope="session")
def kas_url_attr() -> str:
    return os.getenv("KASURL3", "http://localhost:8383/kas")


@pytest.fixture(scope="session")
def kas_url_ns() -> str:
    return os.getenv("KASURL4", "http://localhost:8484/kas")


@pytest.fixture(scope="module")
def attribute_single_kas_grant(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_value1: str,
    temporary_namespace: abac.Namespace,
) -> abac.Attribute:
    anyof = otdfctl.attribute_create(
        temporary_namespace, "letter", abac.AttributeRule.ANY_OF, ["a"]
    )
    assert anyof.values
    (alpha,) = anyof.values
    assert alpha.value == "a"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "a"
    # Now assign it to the current KAS
    kas_entry_alpha = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_alpha, alpha)
    return anyof


@pytest.fixture(scope="module")
def attribute_two_kas_grant_or(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_value1: str,
    kas_url_value2: str,
    temporary_namespace: abac.Namespace,
):
    anyof = otdfctl.attribute_create(
        temporary_namespace, "letra", abac.AttributeRule.ANY_OF, ["alpha", "beta"]
    )
    assert anyof.values
    alpha, beta = anyof.values
    assert alpha.value == "alpha"
    assert beta.value == "beta"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    # Now assign it to the current KAS
    kas_entry_alpha = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_alpha, alpha)

    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value2,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, beta)
    return anyof


@pytest.fixture(scope="module")
def attribute_two_kas_grant_and(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_value1: str,
    kas_url_value2: str,
    temporary_namespace: abac.Namespace,
):
    allof = otdfctl.attribute_create(
        temporary_namespace, "ot", abac.AttributeRule.ALL_OF, ["alef", "bet", "gimmel"]
    )
    assert allof.values
    alef, bet, gimmel = allof.values
    assert alef.value == "alef"
    assert bet.value == "bet"
    assert gimmel.value == "gimmel"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm1 = otdfctl.scs_map(sc, alef)
    assert sm1.attribute_value.value == "alef"
    sm2 = otdfctl.scs_map(sc, bet)
    assert sm2.attribute_value.value == "bet"
    # Now assign it to the current KAS
    kas_entry_alpha = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_alpha, alef)

    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value2,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, bet)

    return allof


@pytest.fixture(scope="module")
def one_attribute_attr_kas_grant(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_attr: str,
    temporary_namespace: abac.Namespace,
):
    anyof = otdfctl.attribute_create(
        temporary_namespace, "attrgrant", abac.AttributeRule.ANY_OF, ["alpha"]
    )
    assert anyof.values
    (alpha,) = anyof.values
    assert alpha.value == "alpha"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    # Now assign it to the current KAS
    kas_entry_alpha = otdfctl.kas_registry_create_if_not_present(
        kas_url_attr,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_attr(kas_entry_alpha, anyof)

    return anyof


@pytest.fixture(scope="module")
def attr_and_value_kas_grants_or(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_attr: str,
    kas_url_value1: str,
    temporary_namespace: abac.Namespace,
):
    anyof = otdfctl.attribute_create(
        temporary_namespace,
        "attrorvalgrant",
        abac.AttributeRule.ANY_OF,
        ["alpha", "beta"],
    )
    assert anyof.values
    (alpha, beta) = anyof.values
    assert alpha.value == "alpha"
    assert beta.value == "beta"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    # Now assign it to the current KAS
    kas_entry_attr = otdfctl.kas_registry_create_if_not_present(
        kas_url_attr,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_attr(kas_entry_attr, anyof)
    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, beta)

    return anyof


@pytest.fixture(scope="module")
def attr_and_value_kas_grants_and(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_attr: str,
    kas_url_value1: str,
    temporary_namespace: abac.Namespace,
):
    allof = otdfctl.attribute_create(
        temporary_namespace,
        "attrandvalgrant",
        abac.AttributeRule.ALL_OF,
        ["alpha", "beta"],
    )
    assert allof.values
    (alpha, beta) = allof.values
    assert alpha.value == "alpha"
    assert beta.value == "beta"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    sm2 = otdfctl.scs_map(sc, beta)
    assert sm2.attribute_value.value == "beta"
    # Now assign it to the current KAS
    kas_entry_attr = otdfctl.kas_registry_create_if_not_present(
        kas_url_attr,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_attr(kas_entry_attr, allof)
    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, beta)

    return allof


@pytest.fixture(scope="module")
def one_attribute_ns_kas_grant(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_ns: str,
    temporary_namespace: abac.Namespace,
):
    anyof = otdfctl.attribute_create(
        temporary_namespace, "nsgrant", abac.AttributeRule.ANY_OF, ["alpha"]
    )
    assert anyof.values
    (alpha,) = anyof.values
    assert alpha.value == "alpha"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    # Now assign it to the current KAS
    kas_entry_ns = otdfctl.kas_registry_create_if_not_present(
        kas_url_ns,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_ns(kas_entry_ns, temporary_namespace)

    return anyof


@pytest.fixture(scope="module")
def ns_and_value_kas_grants_or(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_value1: str,
    kas_url_ns: str,
):
    temp_namespace = create_temp_namesapce(otdfctl)
    anyof = otdfctl.attribute_create(
        temp_namespace,
        "nsorvalgrant",
        abac.AttributeRule.ANY_OF,
        ["alpha", "beta"],
    )
    assert anyof.values
    (alpha, beta) = anyof.values
    assert alpha.value == "alpha"
    assert beta.value == "beta"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    # Now assign it to the current KAS
    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, beta)
    kas_entry_ns = otdfctl.kas_registry_create_if_not_present(
        kas_url_ns,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_ns(kas_entry_ns, temp_namespace)

    return anyof


@pytest.fixture(scope="module")
def ns_and_value_kas_grants_and(
    otdfctl: abac.OpentdfCommandLineTool,
    kas_url_value1: str,
    kas_url_ns: str,
):
    temp_namespace = create_temp_namesapce(otdfctl)
    allof = otdfctl.attribute_create(
        temp_namespace,
        "nsandvalgrant",
        abac.AttributeRule.ALL_OF,
        ["alpha", "beta"],
    )
    assert allof.values
    (alpha, beta) = allof.values
    assert alpha.value == "alpha"
    assert beta.value == "beta"

    # Then assign it to all clientIds = opentdf-sdk
    sc = otdfctl.scs_create(
        [
            abac.SubjectSet(
                condition_groups=[
                    abac.ConditionGroup(
                        boolean_operator=abac.ConditionBooleanTypeEnum.OR,
                        conditions=[
                            abac.Condition(
                                subject_external_selector_value=".clientId",
                                operator=abac.SubjectMappingOperatorEnum.IN,
                                subject_external_values=["opentdf", "opentdf-sdk"],
                            )
                        ],
                    )
                ]
            )
        ],
    )
    sm = otdfctl.scs_map(sc, alpha)
    assert sm.attribute_value.value == "alpha"
    sm2 = otdfctl.scs_map(sc, beta)
    assert sm2.attribute_value.value == "beta"
    # Now assign it to the current KAS
    kas_entry_beta = otdfctl.kas_registry_create_if_not_present(
        kas_url_value1,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_value(kas_entry_beta, beta)
    kas_entry_ns = otdfctl.kas_registry_create_if_not_present(
        kas_url_ns,
        load_cached_kas_keys(),
    )
    otdfctl.grant_assign_ns(kas_entry_ns, temp_namespace)

    return allof


@pytest.fixture(scope="module")
def hs256_key():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


@pytest.fixture(scope="module")
def rs256_keys():
    # Generate an RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Convert to string with escaped newlines
    private_pem_str = private_pem.decode("utf-8")
    public_pem_str = public_pem.decode("utf-8")

    return private_pem_str, public_pem_str


def write_assertion_to_file(
    file_name: str, assertion_list: list[assertions.Assertion] = []
):
    as_file = f"{tmp_dir}test-assertion-{file_name}.json"
    assertion_json = json.dumps(to_jsonable_python(assertion_list, exclude_none=True))
    with open(as_file, "w") as f:
        f.write(assertion_json)
    return as_file


@pytest.fixture(scope="module")
def assertion_file_no_keys():
    assertion_list = [
        assertions.Assertion(
            appliesToState="encrypted",
            id="424ff3a3-50ca-4f01-a2ae-ef851cd3cac0",
            scope="tdo",
            statement=assertions.Statement(
                format="json+stanag5636",
                schema="urn:nato:stanag:5636:A:1:elements:json",
                value='{"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"SECRET","catl":[{"type":"P","name":"Releasable To","vals":["usa"]}],"dcr":"2024-10-21T20:47:36Z"},"context":{"[@base](https://github.com/base)":"urn:nato:stanag:5636:A:1:elements:json"}}',
            ),
            type="handling",
        )
    ]
    return write_assertion_to_file("assertion_1_no_signing_key", assertion_list)


@pytest.fixture(scope="module")
def assertion_file_rs_and_hs_keys(hs256_key: str, rs256_keys: tuple[str, str]) -> str:
    rs256_private, _ = rs256_keys
    assertion_list = [
        assertions.Assertion(
            appliesToState="encrypted",
            id="assertion1",
            scope="tdo",
            statement=assertions.Statement(
                format="json+stanag5636",
                schema="urn:nato:stanag:5636:A:1:elements:json",
                value='{"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"SECRET","catl":[{"type":"P","name":"Releasable To","vals":["usa"]}],"dcr":"2024-10-21T20:47:36Z"},"context":{"[@base](https://github.com/base)":"urn:nato:stanag:5636:A:1:elements:json"}}',
            ),
            type="handling",
            signingKey=assertions.AssertionKey(
                alg="HS256",
                key=hs256_key,
            ),
        ),
        assertions.Assertion(
            appliesToState="encrypted",
            id="assertion2",
            scope="tdo",
            statement=assertions.Statement(
                format="json+stanag5636",
                schema="urn:nato:stanag:5636:A:1:elements:json",
                value='{"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"SECRET","catl":[{"type":"P","name":"Releasable To","vals":["usa"]}],"dcr":"2024-10-21T20:47:36Z"},"context":{"[@base](https://github.com/base)":"urn:nato:stanag:5636:A:1:elements:json"}}',
            ),
            type="handling",
            signingKey=assertions.AssertionKey(
                alg="RS256",
                key=rs256_private,
            ),
        ),
    ]
    return write_assertion_to_file("assertion1_hs_assertion2_rs", assertion_list)


def write_assertion_verification_keys_to_file(
    file_name: str,
    assertion_verificaiton_keys: assertions.AssertionVerificationKeys,
):
    as_file = f"{tmp_dir}test-assertion-verification-{file_name}.json"
    assertion_verification_json = json.dumps(
        to_jsonable_python(assertion_verificaiton_keys, exclude_none=True)
    )
    with open(as_file, "w") as f:
        f.write(assertion_verification_json)
    return as_file


@pytest.fixture(scope="module")
def assertion_verification_file_rs_and_hs_keys(hs256_key: str, rs256_keys: tuple[str, str]) -> str:
    _, rs256_public = rs256_keys
    assertion_verification = assertions.AssertionVerificationKeys(
        keys={
            "assertion1": assertions.AssertionKey(
                alg="HS256",
                key=hs256_key,
            ),
            "assertion2": assertions.AssertionKey(
                alg="RS256",
                key=rs256_public,
            ),
        }
    )
    return write_assertion_verification_keys_to_file(
        "assertion1_hs_assertion2_rs", assertion_verification
    )
