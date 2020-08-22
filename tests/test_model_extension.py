import pytest
from pydantic import ValidationError

from .factories import OpenAPIDocFactory, OperationFactory
from .models import (
    OpenAPI3Document,
    Operation,
    Server,
)
from .secondary_models import (
    OpenAPI3Document as ReExtendedOpenAPI3Document,
)


def test_basics():
    yaml_operation = OperationFactory()
    yaml_operation["x-apigraph-backlinks"] = {
        "link-id": {
            "value": "whatever",
        }
    }
    yaml_doc = OpenAPIDocFactory(**{
        "servers": None,
        "paths__/objects/{id}__get": yaml_operation
    })
    doc = OpenAPI3Document.parse_obj(yaml_doc)

    # default_factory relying on forward refs is also working
    assert isinstance(doc.servers[0], Server)
    assert doc.servers[0].url == "/"

    # our extension fields are working
    operation = doc.paths["/objects/{id}"].get
    assert isinstance(operation, Operation)
    assert hasattr(operation, 'backlinks')
    assert operation.backlinks["link-id"].value == "whatever"


def test_validators():
    yaml_operation = OperationFactory()
    yaml_operation["other"] = 10
    yaml_operation["extra"] = 99
    yaml_doc = OpenAPIDocFactory(**{
        "paths__/objects/{id}__get": yaml_operation
    })
    doc = OpenAPI3Document.parse_obj(yaml_doc)
    assert doc.paths["/objects/{id}"].get.other == 10
    assert doc.paths["/objects/{id}"].get.extra == 99

    # `other` is invalid (validator on `OperationBase`)
    yaml_operation = OperationFactory()
    yaml_operation["other"] = 0
    yaml_operation["extra"] = 99
    yaml_doc = OpenAPIDocFactory(**{
        "paths__/objects/{id}__get": yaml_operation
    })
    with pytest.raises(ValidationError):
        OpenAPI3Document.parse_obj(yaml_doc)

    # `extra` is invalid (validator on `Operation`)
    yaml_operation = OperationFactory()
    yaml_operation["other"] = 10
    yaml_operation["extra"] = 101
    yaml_doc = OpenAPIDocFactory(**{
        "paths__/objects/{id}__get": yaml_operation
    })
    with pytest.raises(ValidationError):
        OpenAPI3Document.parse_obj(yaml_doc)


def test_root_validators():
    # root validator on `OperationBase` (assert extra > other)
    yaml_operation = OperationFactory()
    yaml_operation["other"] = 20
    yaml_operation["extra"] = 15
    yaml_doc = OpenAPIDocFactory(**{
        "paths__/objects/{id}__get": yaml_operation
    })
    with pytest.raises(ValidationError):
        OpenAPI3Document.parse_obj(yaml_doc)

    # root validator on `Operation` (assert extra < max_extra)
    yaml_operation = OperationFactory()
    yaml_operation["other"] = 15
    yaml_operation["max_extra"] = 50
    yaml_operation["extra"] = 51
    yaml_doc = OpenAPIDocFactory(**{
        "paths__/objects/{id}__get": yaml_operation
    })
    with pytest.raises(ValidationError):
        OpenAPI3Document.parse_obj(yaml_doc)


def test_extension_field_needs_ref_to_base_model():
    pass


def test_extension_field_needs_ref_to_extended_model():
    pass


def test_non_extensible_models_no_extra_fields():
    pass


def test_extension_model_config_inheritance():
    pass


def test_base_model_inherit_from_base_model():
    # `ImplicitOAuthFlow` etc
    pass


def test_extend_one_level_extended_model_method_inheritance():
    """
    See `extra` and `method` on `Operation` and `OperationBase` in tests.models
    (top model method does super+extra)
    """
    yaml_doc = OpenAPIDocFactory()
    doc = OpenAPI3Document.parse_obj(yaml_doc)
    operation = doc.paths["/objects/{id}"].get
    assert operation.method() == 14  # 11 + 3 (both default values)

    yaml_doc = OpenAPIDocFactory(**{"paths__/objects/{id}__get__extra": 20})
    doc = OpenAPI3Document.parse_obj(yaml_doc)
    operation = doc.paths["/objects/{id}"].get
    assert operation.method() == 23


def test_extend_two_levels_extended_model():
    """
    Can we extend a model that itself is an extended model from another module
    """
    yaml_doc = OpenAPIDocFactory()
    doc = ReExtendedOpenAPI3Document.parse_obj(yaml_doc)
    operation = doc.paths["/objects/{id}"].get
    assert operation.method() == 27  # 14 + 13 (adding values from all supers)

    # yaml_doc = OpenAPIDocFactory(**{"paths__/objects/{id}__get__extra": 20})
    # doc = ReExtendedOpenAPI3Document.parse_obj(yaml_doc)
    # operation = doc.paths["/objects/{id}"].get
    # assert operation.method() == 23


def test_install_models_exceptions():
    pass
