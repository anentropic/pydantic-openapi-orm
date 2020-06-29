from pathlib import Path

import pytest

from openapi_orm.loader import load_doc

from .models import (
    BacklinkChain,
    BacklinkOperation,
    BacklinkParameter,
    OpenAPI3Document,
    Operation,
    Server,
)


@pytest.fixture
def extensions():
    path = Path(__file__).parent / Path("fixtures/openapi3/extensions.yaml")
    return OpenAPI3Document.parse_obj(load_doc(path))


def test_basics(extensions):
    # all our extension fields are working
    operation = extensions.paths["/pets/{petId}"].get
    assert isinstance(operation, Operation)
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
    # default_factory relying on forward refs is also working
    assert isinstance(extensions.servers[0], Server)


def test_extension_field_needs_ref_to_model(extensions):
    pass


def test_non_extensible_models_no_extra_fields(extensions):
    pass


def test_extension_model_config_inheritance(extensions):
    pass


def test_base_model_inherit_from_base_model(extensions):
    # `ImplicitOAuthFlow` etc
    pass


def test_extend_already_extended_model(extensions):
    operation = extensions.paths["/pets/{petId}"].get
    assert operation.method() == 5


def test_install_models_exceptions(extensions):
    pass
