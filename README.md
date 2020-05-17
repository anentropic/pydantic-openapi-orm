# pydantic-openapi-orm
Project status: still in Alpha

A set of Pydantic models which can be instantiated from an OpenAPI 3 spec.

https://en.wikipedia.org/wiki/Object-relational_mapping
> Object-relational mapping (ORM, O/RM, and O/R mapping tool) in computer science is a programming technique for converting data between incompatible type systems using object-oriented programming languages.

So... I'm using this quote to justify stretching the usual db-centric understanding of what an ORM is.

In this case we're taking the loosely-typed JSON/YAML of an OpenAPI document and loading it into a set of Pydantic models which validate the input against the type system defined by the OpenAPI 3 specification, and return an OO object heirarchy.

Basically it's just a nicer way of working with an api schema than the pile of dictionaries you get from parsing the JSON or YAML.

### Usage

OpenAPI documents can contain `$ref` keys which are [JSON Reference](https://tools.ietf.org/html/draft-pbryan-zyp-json-ref-03) values, potentially pointing via URI to a value in another OpenAPI doc.

No prob, there are libs like [jsonref](https://pypi.org/project/jsonref/) which converts the `$ref` keys into lazy proxies that allows us to access those values transparently. But, OpenAPI commonly uses YAML rather than JSON.

So pydantic-openapi-orm provides a custom JsonRef loader that will traverse references between OpenAPI docs regardless of whether they are JSON or YAML format. Usage looks like this:

```python
from openapi_orm.loader import load_doc
from openapi_orm.models import OpenAPI3Document


petstore = OpenAPI3Document.parse_obj(
    load_doc(
        "https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v3.0/petstore.yaml"
    )
)

for path, path_info in petstore.paths:
    print(path)
    print(path_info.description)
```

Note that `load_doc` takes a URI as the arg. It will also accept a `Path` object, in which case it is assumed you're loading a local file (the Path will be used as a `file://` URI internally):


```python
from pathlib import Path

from openapi_orm.loader import load_doc
from openapi_orm.models import OpenAPI3Document


path = Path("fixtures/openapi3/petstore.yaml")
petstore = OpenAPI3Document.parse_obj(load_doc(path))

for path, path_info in petstore.paths:
    print(path)
    print(path_info.description)
```

You'll notice also that there are still some dictionaries in the object heirarchy. This is because, of course, some parts of the spec will have arbitrary names so it kinda has to be that way.

For example:
```python
assert (
    petstore
    .paths["/pets"]
    .get
    .responses["200"]
    .content["application/json"]
    .schema_
    .type_
) == "array"
```

You'll see here a couple of other quirks. Namely `schema_` has a suffix to avoid clash with Pydantic's existing `schema` attr, and same for `type_` but to avoid clash with the Python builtin.
