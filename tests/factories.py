import factory


class LicenseFactory(factory.DictFactory):
    name = "MIT"


class InfoFactory(factory.DictFactory):
    version = "1.0.0"
    title = "Example Doc"
    license = factory.SubFactory(LicenseFactory)


class ServerFactory(factory.DictFactory):
    url = factory.Faker("url")
    description = factory.Faker("sentence")


class MediaTypeFactory(factory.DictFactory):
    schema = factory.Dict({
        "type": "object",
        "required": [
            "id",
            "name",
        ],
        "properties": {
            "id": {
                "type": "integer",
                "format": "int64",
            },
            "name": {
                "type": "string",
            },
        },
    })


class ResponseFactory(factory.DictFactory):
    description = factory.Faker("sentence")
    content = factory.Dict({
        "application/json": factory.SubFactory(MediaTypeFactory)
    })


class ParameterFactory(factory.DictFactory):
    class Meta:
        rename = {
            "in_": "in",
        }

    name = "id"
    in_ = "path"
    description = factory.Faker("sentence")
    schema = factory.Dict({
        "type": "string",
    })


class OperationFactory(factory.DictFactory):
    summary = factory.Faker("sentence")
    operationId = factory.Faker("slug")
    parameters = factory.List([
        factory.SubFactory(ParameterFactory),
    ])
    responses = factory.Dict({
        "200": factory.SubFactory(ResponseFactory),
        "default": factory.SubFactory(ResponseFactory),
    })


class PathItemFactory(factory.DictFactory):
    get = factory.SubFactory(OperationFactory)


class OpenAPIDocFactory(factory.DictFactory):
    openapi = "3.0.0"
    info = factory.SubFactory(InfoFactory)
    servers = factory.List([factory.SubFactory(ServerFactory)])
    paths = factory.Dict({
        "/objects/{id}": factory.SubFactory(PathItemFactory),
    })
