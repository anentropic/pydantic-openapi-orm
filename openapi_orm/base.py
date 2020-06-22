import abc
import re
from copy import deepcopy
from enum import Enum
from types import ModuleType
from typing import (
    Any,
    Dict,
    ForwardRef,
    List,
    Optional,
    Union,
)

from pydantic import (
    BaseModel as PydanticBaseModel,
    conint,
    constr,
    EmailStr,
    Field,
    HttpUrl,
    PositiveInt,
    root_validator,
    validator,
)
from pydantic.main import ModelMetaclass

# TODO: replace all Any with Optional[object] ?

# all references to an `ExtensibleModel` should be via a `ForwardRef`
# this allows us to construct extended versions of these models and
# then call `OpenAPI3Document.update_forward_refs` and passing the
# extended models as `localns`


def check_unique(val: List[Any]):
    """
    We can't do the `len(set(val))` trick because `val` may not
    be hashable...
    """
    seen = []
    for item in val:
        if item in seen:
            raise ValueError(
                f"values in list must be unique, found duplicate: {item!r}"
            )
        seen.append(val)
    return val


def hyphenated(name: str) -> str:
    # TODO this is mostly unused, due to camelCase in OpenAPI... should we do
    # auto CamelCase->snake_case aliasing instead?
    # extension properties like `x-whatever-whatever` can use this by default
    # (but only if model is explicitly extended, `extra` attrs are not aliased)
    return name.replace("_", "-")


_MODEL_NAMESPACES = {}


class ORMModelMetaclass(ModelMetaclass):
    def __new__(mcs, name, bases, namespace, **kwargs):  # noqa C901
        # stash the namespace so we can later construct a new class
        cls_namespace = {}
        for key, value in namespace.items():
            if key == "__annotations__":
                # we need to preserve the ForwardRefs in their unresolved state
                # (ModelMetaclass.__new__ has some code that resolves them)
                cls_namespace[key] = deepcopy(value)
            else:
                cls_namespace[key] = value
        _MODEL_NAMESPACES[name] = (bases, cls_namespace)
        # then return the model cls as normal
        return super().__new__(mcs, name, bases, namespace, **kwargs)


class ExtendedModelMetaclass(ModelMetaclass):
    def __new__(mcs, name, _, namespace, **kwargs):  # noqa C901
        """
        NOTE: this has to run after all the base models are constructed
        (we can assume that will be the case since you have to import
        `base.ExtendedModelMetaclass` in order to extend a model)
        """
        # merge the base model namespace with the extended model namespace
        # to make a single composite model (we're not doing OOP inheritance)
        bases, cls_namespace = _MODEL_NAMESPACES[name]
        assert ExtensibleModel in bases
        new_annotations = namespace.pop("__annotations__", {})
        cls_namespace.setdefault("__annotations__", {}).update(new_annotations)
        cls_namespace.update(namespace)
        return ModelMetaclass.__new__(
            ModelMetaclass, name, bases, cls_namespace, **kwargs
        )


class BaseModel(PydanticBaseModel, abc.ABC):
    class Config:
        use_enum_values = True
        allow_mutation = False
        alias_generator = hyphenated


class ExtensibleModel(PydanticBaseModel, abc.ABC):
    """
    Mark a model as allowing user-defined extensions, as per Open API spec

    (in Open API 3.0, any extension field names MUST be prefixed with `x-`
    ...apparently in Open API 3.1 this requirement will be removed)
    """
    class Config(BaseModel.Config):
        extra = "allow"


class Contact(ExtensibleModel, metaclass=ORMModelMetaclass):
    name: Optional[str]
    url: HttpUrl
    email: EmailStr


class License(ExtensibleModel, metaclass=ORMModelMetaclass):
    name: str
    url: Optional[HttpUrl]


class Info(ExtensibleModel, metaclass=ORMModelMetaclass):
    title: str
    description: Optional[str]
    termsOfService: Optional[str]
    contact: ForwardRef("Optional[Contact]")
    license: ForwardRef("Optional[License]")
    version: str


class ServerVariable(ExtensibleModel, metaclass=ORMModelMetaclass):
    enum: Optional[List[str]]
    default: str
    description: Optional[str]

    _check_enum = validator("enum", allow_reuse=True)(check_unique)


class Server(ExtensibleModel, metaclass=ORMModelMetaclass):
    url: str  # NO VALIDATION: MAY be relative, MAY have { } for var substitutions
    description: Optional[str]
    variables: ForwardRef("Optional[Dict[str, ServerVariable]]")


class ExternalDocumentation(ExtensibleModel, metaclass=ORMModelMetaclass):
    description: Optional[str]
    url: HttpUrl


class Discriminator(BaseModel, metaclass=ORMModelMetaclass):
    propertyName: str
    mapping: Optional[Dict[str, str]]


class XMLObj(ExtensibleModel, metaclass=ORMModelMetaclass):
    name: Optional[str]
    namespace: Optional[HttpUrl]
    prefix: Optional[str]
    attribute: bool = False
    wrapped: bool = False  # takes effect only when defined alongside type being array (outside the items)


class Reference(BaseModel, metaclass=ORMModelMetaclass):
    ref: str = Field(..., alias="$ref")


# `Reference` must come first!
# (pydantic tries to instantiate members of Union type from L-R
# and takes the first one that succeeds)
SchemaOrRef = "Union[Reference, Schema]"


class Schema(ExtensibleModel, metaclass=ORMModelMetaclass):
    """
    This class is a combination of JSON Schema rules:
    https://tools.ietf.org/html/draft-wright-json-schema-validation-00

    With some overrides and extra fields as defined by Open API here:
    https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#schemaObject
    """
    class Config:
        # allows these fields to remain unset (not possible via `Field(...)`)
        fields = {
            "type_": {"alias": "type"},
            "not_": {"alias": "not"},
            "format_": {"alias": "format"},
        }

    title: Optional[str]
    multipleOf: Optional[PositiveInt]
    maximum: Optional[float]
    exclusiveMaximum: bool = False
    minimum: Optional[float]
    exclusiveMinimum: bool = False
    maxLength: Optional[PositiveInt]
    minLength: Optional[conint(ge=0)]
    pattern: Optional[str]
    maxItems: Optional[conint(ge=0)]
    minItems: Optional[conint(ge=0)]
    uniqueItems: bool = False
    maxProperties: Optional[conint(ge=0)]
    minProperties: Optional[conint(ge=0)]
    required: Optional[List[str]]
    enum: Optional[List[Any]]

    type_: Optional[str]
    allOf: ForwardRef(f"Optional[List[{SchemaOrRef}]]")
    oneOf: ForwardRef(f"Optional[List[{SchemaOrRef}]]")
    anyOf: ForwardRef(f"Optional[List[{SchemaOrRef}]]")
    not_: ForwardRef(f"Optional[List[{SchemaOrRef}]]")
    items: ForwardRef(f"Optional[{SchemaOrRef}]")
    properties: ForwardRef(f"Optional[Dict[str, {SchemaOrRef}]]")
    additionalProperties: ForwardRef(f"Union[bool, {SchemaOrRef}]") = True
    description: Optional[str]
    format_: Optional[str]
    default: Any

    nullable: bool = False
    discriminator: Optional[Discriminator]
    externalDocs: ForwardRef("Optional[ExternalDocumentation]")
    example: Any
    deprecated: bool = False

    # relevant only for "properties" schemas
    readOnly: bool = False
    writeOnly: bool = False
    xml: ForwardRef("Optional[XMLObj]")

    _check_uniques = validator("required", "enum", allow_reuse=True)(check_unique)

    @validator("required")
    def check_required(cls, v):
        assert len(v) > 0, "`required` must be non-empty if present"
        return v

    @validator("enum")
    def check_enum(cls, v):
        assert len(v) > 0, "`enum` must be non-empty if present"
        return v

    @root_validator
    def check_items(cls, values):
        if values.get("type") == "array":
            assert values.get("items"), "`items` must be present when `type='array'`"
        return values

    @root_validator
    def check_discriminator(cls, values):
        # The discriminator object is legal only when using one of the composite keywords oneOf, anyOf, allOf.
        if values.get("discriminator") is not None and (
            not any(values.get(key) is not None
                    for key in {"oneOf", "anyOf", "allOf"})
        ):
            raise ValueError(
                "`discriminator` is legal only when using one of the composite keywords `oneOf`, `anyOf`, `allOf`."
            )
        return values


class Example(ExtensibleModel, metaclass=ORMModelMetaclass):
    summary: Optional[str]
    description: Optional[str]
    value: Any
    externalValue: Optional[HttpUrl]

    @root_validator
    def check_value(cls, values):
        if values.get("value") and values.get("externalValue"):
            raise ValueError("`value` and `externalValue` are mutually-exclusive")
        return values


class Encoding(ExtensibleModel, metaclass=ORMModelMetaclass):
    contentType: Optional[str]
    headers: Optional[Dict[str, Union[Reference, "Header"]]]
    style: Optional[str]
    explode: bool = False
    allowReserved: bool = False

    @root_validator
    def default_explode(cls, values):
        if "explode" not in values and values.get("style") is Style.FORM:
            values['explode'] = True
        return values


class MediaType(ExtensibleModel, metaclass=ORMModelMetaclass):
    class Config:
        fields = {
            "schema_": {"alias": "schema"}
        }

    schema_: ForwardRef(f"Optional[{SchemaOrRef}]")
    example: Any
    examples: ForwardRef("Optional[Dict[str, Union[Reference, Example]]]")
    encoding: ForwardRef("Optional[Dict[str, Encoding]]")

    @root_validator
    def check_examples(cls, values):
        """
        In OpenAPI v3.1 the Schema Object example keyword is deprecated, so you
        should start using examples in your API description documents.
        """
        if values.get("example") and values.get("examples"):
            raise ValueError("`example` and `examples` are mutually-exclusive")
        return values


class In(str, Enum):
    QUERY = "query"
    HEADER = "header"
    PATH = "path"
    COOKIE = "cookie"


class Style(str, Enum):
    MATRIX = "matrix"
    LABEL = "label"
    FORM = "form"
    SIMPLE = "simple"
    SPACE_DELIMITED = "spaceDelimited"
    PIPE_DELIMITED = "pipeDelimited"
    DEEP_OBJECT = "deepObject"


IN_STYLES_MAP = {
    In.QUERY: {
        Style.FORM,
        Style.SPACE_DELIMITED,
        Style.PIPE_DELIMITED,
        Style.DEEP_OBJECT,
    },
    In.HEADER: {
        Style.SIMPLE,
    },
    In.PATH: {
        Style.MATRIX,
        Style.LABEL,
        Style.SIMPLE,
    },
    In.COOKIE: {
        Style.FORM,
    }
}

IN_STYLE_DEFAULTS = {
    In.QUERY: Style.FORM,
    In.HEADER: Style.SIMPLE,
    In.PATH: Style.SIMPLE,
    In.COOKIE: Style.FORM,
}


class Header(BaseModel, metaclass=ORMModelMetaclass):
    class Config:
        fields = {
            "schema_": {"alias": "schema"}
        }

    description: Optional[str]
    required: bool = False
    deprecated: bool = False
    allowEmptyValue: bool = False

    style: Optional[Style]
    explode: bool = False
    allowReserved: bool = False
    schema_: ForwardRef(f"Optional[{SchemaOrRef}]")
    example: Any
    examples: ForwardRef("Optional[Dict[str, Union[Reference, Example]]]")

    content: ForwardRef("Optional[Dict[str, MediaType]]")

    @root_validator
    def check_allow_empty_value(cls, values):
        if values.get("allowEmptyValue"):
            raise ValueError("allowEmptyValue=True is not valid for Header")
        return values

    @root_validator
    def check_style_and_explode(cls, values):
        style = values.get("style")
        if style:
            assert style in IN_STYLES_MAP[In.HEADER]
        else:
            values["style"] = IN_STYLE_DEFAULTS[In.HEADER]
        return values

    @root_validator
    def check_allow_reserved(cls, values):
        if values.get("allowReserved"):
            raise ValueError("allowReserved=True is not valid for Header")
        return values

    @root_validator
    def check_examples(cls, values):
        """
        In OpenAPI v3.1 the Schema Object example keyword is deprecated, so you
        should start using examples in your API description documents.
        """
        if values.get("example") and values.get("examples"):
            raise ValueError("`example` and `examples` are mutually-exclusive")
        return values

    @validator("content")
    def check_content(cls, v):
        assert len(v) == 1
        return v


class Parameter(ExtensibleModel, metaclass=ORMModelMetaclass):
    class Config:
        fields = {
            "schema_": {"alias": "schema"}
        }

    name: str
    in_: In = Field(..., alias="in")
    description: Optional[str]
    required: bool = False
    deprecated: bool = False
    allowEmptyValue: bool = False

    style: Optional[Style]
    explode: bool = False
    allowReserved: bool = False
    schema_: ForwardRef(f"Optional[{SchemaOrRef}]")
    example: Any
    examples: ForwardRef("Optional[Dict[str, Union[Reference, Example]]]")

    content: ForwardRef("Optional[Dict[str, MediaType]]")

    @root_validator
    def check_required(cls, values):
        if values["in_"] is In.PATH:
            assert values['required'] is True
        return values

    @root_validator
    def check_allow_empty_value(cls, values):
        if values.get("allowEmptyValue") and values["in_"] is not In.QUERY:
            raise ValueError("allowEmptyValue=True is only valid for in='query'")
        return values

    @root_validator
    def check_style_and_explode(cls, values):
        style = values.get("style")
        if style:
            assert style in IN_STYLES_MAP[values["in_"]]
        else:
            values["style"] = IN_STYLE_DEFAULTS[values["in_"]]

        if "explode" not in values and values.get("style") is Style.FORM:
            values["explode"] = True

        return values

    @root_validator
    def check_allow_reserved(cls, values):
        if values.get("allowReserved") and values["in_"] is not In.QUERY:
            raise ValueError("allowReserved=True is only valid for in='query'")
        return values

    @root_validator
    def check_examples(cls, values):
        """
        In OpenAPI v3.1 the Schema Object example keyword is deprecated, so you
        should start using examples in your API description documents.
        """
        if values.get("example") and values.get("examples"):
            raise ValueError("`example` and `examples` are mutually-exclusive")
        return values

    @validator("content")
    def check_content(cls, v):
        assert len(v) == 1
        return v


class RequestBody(ExtensibleModel, metaclass=ORMModelMetaclass):
    description: Optional[str]
    content: ForwardRef("Dict[str, MediaType]")
    required: bool = False


class Link(ExtensibleModel, metaclass=ORMModelMetaclass):
    operationRef: Optional[str]
    operationId: Optional[str]
    parameters: Optional[Dict[str, Any]]  # TODO: {expression} | Any
    requestBody: Optional[Any]  # TODO: {expression} | Any
    description: Optional[str]
    server: ForwardRef("Optional[Server]")
    # https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#runtimeExpression

    @root_validator
    def check_operation(cls, values):
        # TODO: also... oneOf Ref or Id required
        if values.get("operationRef") and values.get("operationId"):
            raise ValueError(
                "`operationRef` and `operationId` are mutually-exclusive"
            )
        return values


class Response(ExtensibleModel, metaclass=ORMModelMetaclass):
    description: Optional[str]
    headers: ForwardRef("Optional[Dict[str, Union[Reference, Header]]]")
    content: ForwardRef("Optional[Dict[str, MediaType]]")
    links: ForwardRef("Optional[Dict[str, Union[Reference, Link]]]")


HTTP_STATUS_RE = re.compile(r"^[1-5][X0-9]{2}|default$")


def check_responses(val):
    for key in val:
        if not HTTP_STATUS_RE.match(key):
            raise ValueError(f"{key} is not a valid Response key")
    return val


Callback = "Dict[str, PathItem]"

SecurityRequirement = Dict[str, List[str]]
# Each name MUST correspond to a security scheme which is declared in the
# Security Schemes under the Components Object. (TODO)
# If the security scheme is of type "oauth2" or "openIdConnect", then the value
# is a list of scope names required for the execution. For other security
# scheme types, the array MUST be empty.


class Operation(ExtensibleModel, metaclass=ORMModelMetaclass):
    tags: Optional[List[str]]
    summary: Optional[str]
    description: Optional[str]
    externalDocs: ForwardRef("Optional[ExternalDocumentation]")
    operationId: Optional[str]
    parameters: ForwardRef("Optional[List[Union[Reference, Parameter]]]")
    requestBody: ForwardRef("Optional[Union[Reference, RequestBody]]")
    responses: ForwardRef("Dict[str, Union[Reference, Response]]")
    callbacks: ForwardRef(f"Optional[Dict[str, Union[Reference, {Callback}]]]")
    deprecated: bool = False
    security: Optional[List[SecurityRequirement]]
    servers: ForwardRef("Optional[List[Server]]")

    _check_parameters = validator("parameters", allow_reuse=True)(check_unique)
    _check_responses = validator("responses", allow_reuse=True)(check_responses)


class PathItem(ExtensibleModel, metaclass=ORMModelMetaclass):
    class Config:
        fields = {
            "ref": {"alias": "$ref"}
        }

    ref: Optional[str]
    summary: Optional[str]
    description: Optional[str]
    get: ForwardRef("Optional[Operation]")
    put: ForwardRef("Optional[Operation]")
    post: ForwardRef("Optional[Operation]")
    delete: ForwardRef("Optional[Operation]")
    options: ForwardRef("Optional[Operation]")
    head: ForwardRef("Optional[Operation]")
    patch: ForwardRef("Optional[Operation]")
    trace: ForwardRef("Optional[Operation]")


class _BaseOAuthFlow(ExtensibleModel, metaclass=ORMModelMetaclass):
    refreshUrl: Optional[HttpUrl]
    scopes: Dict[str, str]


class ImplicitOAuthFlow(_BaseOAuthFlow):
    authorizationUrl: HttpUrl


class AuthorizationCodeOAuthFlow(_BaseOAuthFlow):
    authorizationUrl: HttpUrl
    tokenUrl: HttpUrl


class PasswordOAuthFlow(_BaseOAuthFlow):
    tokenUrl: HttpUrl


class ClientCredentialsOAuthFlow(_BaseOAuthFlow):
    tokenUrl: HttpUrl


OAuthFlow = """
Union[
    ImplicitOAuthFlow,
    AuthorizationCodeOAuthFlow,
    PasswordOAuthFlow,
    ClientCredentialsOAuthFlow,
]
"""


class OAuthFlows(ExtensibleModel, metaclass=ORMModelMetaclass):
    implicit: ForwardRef(f"Optional[{OAuthFlow}]")
    password: ForwardRef(f"Optional[{OAuthFlow}]")
    clientCredentials: ForwardRef(f"Optional[{OAuthFlow}]")
    authorizationCode: ForwardRef(f"Optional[{OAuthFlow}]")


class Type_(str, Enum):
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"


class _BaseSecurityScheme(ExtensibleModel, metaclass=ORMModelMetaclass):
    type_: Type_ = Field(..., alias="type")
    description: Optional[str]


class APIKeySecurityScheme(_BaseSecurityScheme):
    name: str
    in_: In

    @validator("in_")
    def check_in(cls, v):
        if v not in {In.QUERY, In.HEADER, In.COOKIE}:
            raise ValueError(f"{v} is not a valid `in` value")
        return v


class HTTPSecurityScheme(_BaseSecurityScheme):
    scheme: str
    bearerFormat: Optional[str]


class OAuth2SecurityScheme(_BaseSecurityScheme):
    flows: ForwardRef("OAuthFlows")


class OpenIDConnectSecurityScheme(_BaseSecurityScheme):
    openIdConnectUrl: HttpUrl


SecurityScheme = """
Union[
    APIKeySecurityScheme,
    HTTPSecurityScheme,
    OAuth2SecurityScheme,
    OpenIDConnectSecurityScheme,
]
"""


class Components(ExtensibleModel, metaclass=ORMModelMetaclass):
    r"""
    TODO:
    All the fixed fields declared below are objects that MUST use keys that
    match the regular expression: ^[a-zA-Z0-9\.\-_]+$
    """
    schemas: ForwardRef(f"Optional[Dict[str, {SchemaOrRef}]]")
    responses: ForwardRef("Optional[Dict[str, Union[Reference, Response]]]")
    parameters: ForwardRef("Optional[Dict[str, Union[Reference, Parameter]]]")
    examples: ForwardRef("Optional[Dict[str, Union[Reference, Example]]]")
    requestBodies: ForwardRef("Optional[Dict[str, Union[Reference, RequestBody]]]")
    headers: Optional[Dict[str, Union[Reference, Header]]]
    securitySchemes: ForwardRef(f"Optional[Dict[str, Union[Reference, {SecurityScheme}]]]")
    links: ForwardRef("Optional[Dict[str, Union[Reference, Link]]]")
    callbacks: ForwardRef(f"Optional[Dict[str, Union[Reference, {Callback}]]]")


class Tag(ExtensibleModel, metaclass=ORMModelMetaclass):
    name: str
    description: Optional[str]
    externalDocs: ForwardRef("Optional[ExternalDocumentation]")


def default_servers() -> ForwardRef("List[Server]"):
    """
    NOTE:
    Assumes this was called after `OpenAPI3Document.update_forward_refs()`
    """
    Server_ = ForwardRef("Server")._evaluate(globals(), locals())
    Server_.update_forward_refs()
    return [Server_(url="/")]


VersionStr = constr(regex=r'\d+\.\d+\.\d+')


class OpenAPI3Document(ExtensibleModel, metaclass=ORMModelMetaclass):
    """
    See:
    https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md
    """
    openapi: VersionStr = "3.0.2"
    info: ForwardRef("Info")
    servers: ForwardRef("List[Server]") = Field(default_factory=default_servers)
    paths: ForwardRef("Dict[str, PathItem]")
    components: ForwardRef("Optional[Components]")
    security: Optional[List[SecurityRequirement]]
    tags: ForwardRef("Optional[List[Tag]]")
    externalDocs: ForwardRef("Optional[ExternalDocumentation]")


_OPEN_API_MODELS = (
    "Contact",
    "License",
    "Info",
    "ServerVariable",
    "Server",
    "ExternalDocumentation",
    "Discriminator",
    "XMLObj",
    "Reference",
    "Schema",
    "Example",
    "Encoding",
    "MediaType",
    "Header",
    "Parameter",
    "RequestBody",
    "Link",
    "Response",
    "Operation",
    "PathItem",
    "ImplicitOAuthFlow",
    "AuthorizationCodeOAuthFlow",
    "PasswordOAuthFlow",
    "ClientCredentialsOAuthFlow",
    "OAuthFlows",
    "APIKeySecurityScheme",
    "HTTPSecurityScheme",
    "OAuth2SecurityScheme",
    "OpenIDConnectSecurityScheme",
    "Components",
    "Tag",
    "OpenAPI3Document",
)


def install_modules(module: ModuleType, **overrides: ExtensibleModel):
    """
    Generate a 'stack' of OpenAPI ORM models under your own root module
    while supplying any overridden models to substitute into the stack.
    """
    namespace = {
        key: value
        for key, value in globals().items()
        if key not in _OPEN_API_MODELS
    }

    for name, model in overrides.items():
        if name not in _OPEN_API_MODELS:
            raise ValueError(f"`{name}` is not an OpenAPI model name.")
        namespace[name] = model

    for name in _OPEN_API_MODELS:
        if name in overrides:
            continue
        # generate a new verbatim copy of the base model
        bases, cls_namespace = _MODEL_NAMESPACES[name]
        cls_namespace['__module__'] = module.__name__
        model = ModelMetaclass.__new__(ModelMetaclass, name, bases, cls_namespace)
        setattr(module, name, model)
        namespace[name] = model

    # resolve the `ForwardRef`s against our overriden stack
    for name in _OPEN_API_MODELS:
        namespace[name].update_forward_refs(**namespace)

    # TODO: test that Server model can be extended, possible complication
    # due to default factory on OpenAPI3Document
