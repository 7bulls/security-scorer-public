import base64

import pytest
from fastapi.testclient import TestClient

from security_scorer import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def example_metadata_blob() -> bytes:
    with open("example_metadata.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_metadata_blob_misspelled_impact() -> bytes:
    with open("example_metadata_misspelled_impact.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_metadata_blob_misspelled_component_claim() -> bytes:
    with open("example_metadata_misspelled_component_claim.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_metadata_blob_misspelled_component_definition() -> bytes:
    with open("example_metadata_misspelled_component_definition.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_metadata_blob_misspelled_test_name() -> bytes:
    with open("example_metadata_misspelled_test_name.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_metadata_blob_misspelled_vulnerability() -> bytes:
    with open("example_metadata_misspelled_vulnerability.yaml", "rb") as f:
        return f.read()


@pytest.fixture
def example_graphwalker_result() -> bytes:
    with open("TEST-GraphWalker-20210831T230909449.xml", "rb") as f:
        return f.read()


@pytest.fixture
def example_request_with_graphwalker(
    example_metadata_blob, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(example_metadata_blob).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }


@pytest.fixture
def example_request_with_graphwalker_misspelled_impact(
    example_metadata_blob_misspelled_impact, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(example_metadata_blob_misspelled_impact).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }


@pytest.fixture
def example_request_with_graphwalker_misspelled_component_claim(
    example_metadata_blob_misspelled_component_claim, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(
                example_metadata_blob_misspelled_component_claim
            ).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }


@pytest.fixture
def example_request_with_graphwalker_misspelled_component_definition(
    example_metadata_blob_misspelled_component_definition, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(
                example_metadata_blob_misspelled_component_definition
            ).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }


@pytest.fixture
def example_request_with_graphwalker_misspelled_test_name(
    example_metadata_blob_misspelled_test_name, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(
                example_metadata_blob_misspelled_test_name
            ).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }


@pytest.fixture
def example_request_with_graphwalker_misspelled_vulnerability(
    example_metadata_blob_misspelled_vulnerability, example_graphwalker_result
) -> dict:
    return {
        "metadata": {
            "blob": base64.b64encode(
                example_metadata_blob_misspelled_vulnerability
            ).decode(),
        },
        "tool_outputs": {
            "graphwalker": base64.b64encode(example_graphwalker_result).decode(),
        },
    }
