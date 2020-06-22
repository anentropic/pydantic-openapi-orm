from pathlib import Path

import pytest

from openapi_orm.loader import load_doc

from .models import (
    BacklinkChain,
    BacklinkOperation,
    BacklinkParameter,
    OpenAPI3Document,
)


@pytest.fixture
def extensions():
    path = Path(__file__).parent / Path("fixtures/openapi3/extensions.yaml")
    return OpenAPI3Document.parse_obj(load_doc(path))


def test_extensions(extensions):
    operation = extensions.paths["/pets/{petId}"].get
    assert hasattr(operation, 'backlinks')
    assert operation.backlinks == {
        "default": BacklinkChain(
            operations={
                "New Pet": BacklinkOperation(
                    operationRef="#/pets/post",
                    response="200",
                )
            },
            parameters={
                "petId": BacklinkParameter(
                    from_="New Pet",
                    select="$response.body#/id",
                ),
            },
        )
    }
