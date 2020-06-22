from pathlib import Path

import pytest

from openapi_orm.loader import load_doc
from openapi_orm.models import OpenAPI3Document


@pytest.fixture(
    scope="module",
    params=[
        "api-with-examples.yaml",
        "callback-example.yaml",
        "link-example.yaml",
        "petstore-expanded.yaml",
        "petstore.yaml",
        "uspto.yaml",
    ]
)
def example_schema(request):
    path = Path(__file__).parent / Path(f"fixtures/openapi3/{request.param}")
    yield load_doc(f"file://{path}")


@pytest.fixture
def petstore():
    path = Path(__file__).parent / Path("fixtures/openapi3/petstore.yaml")
    return OpenAPI3Document.parse_obj(load_doc(path))


@pytest.fixture
def extensions():
    path = Path(__file__).parent / Path("fixtures/openapi3/extensions.yaml")
    return OpenAPI3Document.parse_obj(load_doc(path))


def test_openapi3_example_schemas(example_schema):
    """
    Simple round-trip test... if we instantiate an `OpenAPI3Document`
    model from the example schema, and then marshall it back to a dict (i.e.
    prior to re-export schema as a yaml file again)... do the dicts match?
    """
    doc = OpenAPI3Document.parse_obj(example_schema)
    serialized = doc.dict(by_alias=True, exclude_unset=True)
    assert serialized == example_schema


def test_refs(petstore):
    ref = (
        petstore
        .paths["/pets"]
        .get
        .responses["200"]
        .content["application/json"]
        .schema_
    )
    # has JsonRef resolved it for us?
    assert ref.type_ == "array"


def test_extensions(extensions):
    # `Config.alias_generator` does not run for `extra` fields
    ext = getattr(
        extensions.paths["/pets/{petId}"].get, 'x-apigraph-backlinks'
    )
    assert ext == {
        'default': {
            'operations': {
                'New Pet': {
                    'operationRef': '#/pets/post',
                    'response': '200',
                },
            },
            'parameters': {
                'petId': {
                    'from': 'New Pet',
                    'select': '$response.body#/id',
                },
            },
        },
    }
