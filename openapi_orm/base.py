import abc
import re
from copy import deepcopy
from functools import wraps
from enum import Enum
from types import ModuleType
from typing import (
    Any,
    Dict,
    ForwardRef,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
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
from pydantic.fields import UndefinedType
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


class ORMModelPlaceholder:
    pass


Namespace = Dict[str, Any]

NamespacesMap = Dict[ORMModelPlaceholder, Tuple[Iterable[Type], Namespace]]

_MODEL_NAMESPACES: NamespacesMap = {}


# oo-oo ah-ah
# (because we need to deepcopy our cls namespaces when stashing them)
UndefinedType.__copy__ = lambda self: self
UndefinedType.__deepcopy__ = lambda self, memo: self


def _deepcopy_namespace(namespace):
    # we need to preserve the ForwardRefs in their unresolved state
    # (multiple concrete models may be derived from stashed attrs)
    return {
        key: deepcopy(value) if key == "__annotations__" else value
        for key, value in namespace.items()
    }


class ORMModelMetaclass(ModelMetaclass):
    """
    We need to be able to construct a new 'stack' of models, with field
    relationships via ForwardRef resolved to use any overriden models

    So we do this hack - we stash the construction namespaces of the models
    in this file and return instead a placeholder class.

    When defining an extended model you can inherit from the placeholder, but
    adding the `ExtendedModelMetaclass` below, and then call `install_models`
    to generate your custom stack and add them to your own module.
    """
    def __new__(mcs, name, bases, namespace, **kwargs):  # noqa C901
        # stash the namespace so we can later construct a new concrete class
        cls_namespace = _deepcopy_namespace(namespace)
        placeholder = type(
            name,
            (ORMModelPlaceholder,) + bases,
            {"__module__": mcs.__module__},
        )
        _MODEL_NAMESPACES[placeholder] = (bases, cls_namespace)
        return placeholder


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
    discriminator: ForwardRef("Optional[Discriminator]")
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
    headers: ForwardRef("Optional[Dict[str, Union[Reference, Header]]]")
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


class _BaseOAuthFlow(ExtensibleModel):
    refreshUrl: Optional[HttpUrl]
    scopes: Dict[str, str]


# TODO: test the model inheritance still works here
class ImplicitOAuthFlow(_BaseOAuthFlow, metaclass=ORMModelMetaclass):
    authorizationUrl: HttpUrl


class AuthorizationCodeOAuthFlow(_BaseOAuthFlow, metaclass=ORMModelMetaclass):
    authorizationUrl: HttpUrl
    tokenUrl: HttpUrl


class PasswordOAuthFlow(_BaseOAuthFlow, metaclass=ORMModelMetaclass):
    tokenUrl: HttpUrl


class ClientCredentialsOAuthFlow(_BaseOAuthFlow, metaclass=ORMModelMetaclass):
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


class _BaseSecurityScheme(ExtensibleModel):
    type_: Type_ = Field(..., alias="type")
    description: Optional[str]


class APIKeySecurityScheme(_BaseSecurityScheme, metaclass=ORMModelMetaclass):
    name: str
    in_: In

    @validator("in_")
    def check_in(cls, v):
        if v not in {In.QUERY, In.HEADER, In.COOKIE}:
            raise ValueError(f"{v} is not a valid `in` value")
        return v


class HTTPSecurityScheme(_BaseSecurityScheme, metaclass=ORMModelMetaclass):
    scheme: str
    bearerFormat: Optional[str]


class OAuth2SecurityScheme(_BaseSecurityScheme, metaclass=ORMModelMetaclass):
    flows: ForwardRef("OAuthFlows")


class OpenIDConnectSecurityScheme(_BaseSecurityScheme, metaclass=ORMModelMetaclass):
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
    headers: ForwardRef("Optional[Dict[str, Union[Reference, Header]]]")
    securitySchemes: ForwardRef(f"Optional[Dict[str, Union[Reference, {SecurityScheme}]]]")
    links: ForwardRef("Optional[Dict[str, Union[Reference, Link]]]")
    callbacks: ForwardRef(f"Optional[Dict[str, Union[Reference, {Callback}]]]")


class Tag(ExtensibleModel, metaclass=ORMModelMetaclass):
    name: str
    description: Optional[str]
    externalDocs: ForwardRef("Optional[ExternalDocumentation]")


_DEPENDENT_FUNCTIONS = []


def depends_on_refs(uninitialised_fallback):
    """
    Primarily intended for case when we have a `Field(default_factory=...)`
    which needs to return an instance of an ORM Model, this will need to
    resolve a forward ref, which in turn will rely upon `install_models`
    having supplied the namespace containing a concretised model stack.
    """
    def inner(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if decorated._namespace is None:
                return uninitialised_fallback(*args, **kwargs)
            return f(*args, **kwargs)
        decorated._namespace = None
        _DEPENDENT_FUNCTIONS.append(decorated)
        return decorated
    return inner


@depends_on_refs(lambda: None)
def default_servers():
    Server_ = ForwardRef("Server")._evaluate(default_servers._namespace, None)
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

    @validator("servers")
    def check_servers(cls, v):
        if not v:
            return default_servers()
        return v


_OPEN_API_MODELS = (
    Contact,
    License,
    Info,
    ServerVariable,
    Server,
    ExternalDocumentation,
    Discriminator,
    XMLObj,
    Reference,
    Schema,
    Example,
    Encoding,
    MediaType,
    Header,
    Parameter,
    RequestBody,
    Link,
    Response,
    Operation,
    PathItem,
    ImplicitOAuthFlow,
    AuthorizationCodeOAuthFlow,
    PasswordOAuthFlow,
    ClientCredentialsOAuthFlow,
    OAuthFlows,
    APIKeySecurityScheme,
    HTTPSecurityScheme,
    OAuth2SecurityScheme,
    OpenIDConnectSecurityScheme,
    Components,
    Tag,
    OpenAPI3Document,
)


class InvalidModelExtension(Exception):
    pass


def get_placeholder_model(
    extended_model: ORMModelPlaceholder
) -> ORMModelPlaceholder:
    def _find_placeholders(
        bases_: Iterable[Type], found: List[Type]
    ) -> List[ORMModelPlaceholder]:
        for base in bases_:
            if base in _OPEN_API_MODELS:
                found.append(base)
            _find_placeholders(base.__bases__, found)
        return found

    found = _find_placeholders(extended_model.__bases__, [])
    if not found:
        raise InvalidModelExtension(
            f"Did not find any ORM Model in bases for {extended_model}."
        )
    if len(found) > 1:
        raise InvalidModelExtension(
            f"Multiple ORM Models ({len(found)}) found in bases for {extended_model}: {found}"
        )
    return found[0]


def _recursive_update_forward_refs(model, namespace: Dict[str, Any]):
    model.update_forward_refs(**namespace)
    for base in model.__bases__:
        if hasattr(base, "update_forward_refs"):
            base.update_forward_refs(**namespace)


def install_models(module: ModuleType, *overrides: ExtensibleModel):
    """
    Generate a 'stack' of OpenAPI ORM models under your own root module
    while supplying any overridden models to substitute into the stack.
    """
    namespace = {
        key: value
        for key, value in globals().items()
        if key not in _OPEN_API_MODELS
    }

    def _gen_model(placeholder: ORMModelPlaceholder, name: str) -> BaseModel:
        bases, cls_namespace = _MODEL_NAMESPACES[placeholder]
        # don't modify the stashed originals
        cls_namespace = _deepcopy_namespace(cls_namespace)

        cls_namespace['__module__'] = module.__name__
        # NOTE: this also potentially triggers some ForwardRef resolution
        return ModelMetaclass.__new__(
            ModelMetaclass, name, bases, cls_namespace
        )

    # generate concrete extended models
    concrete_models = {}
    extended_placeholders = set()
    for extended_model in overrides:
        placeholder = get_placeholder_model(extended_model)
        if placeholder in extended_placeholders:
            raise InvalidModelExtension(
                f"Duplicate base ORM Model in overrides: {extended_model}"
            )
        if placeholder not in _OPEN_API_MODELS:
            raise InvalidModelExtension(
                f"Unrecognised base ORM Model in overrides: {placeholder}"
            )
        # TODO: validate that non-extensible models haven't been extended with
        # extra fields
        extended_placeholders.add(placeholder)

        # TODO: each extended model should also be a (separate) placeholder?
        name = placeholder.__name__
        base_model = _gen_model(placeholder, f"Base{name}")
        model = type(name, (extended_model, base_model), {})
        setattr(module, name, model)
        namespace[name] = model
        concrete_models[placeholder] = model

    # generate concrete cls for remaining models
    for placeholder in _OPEN_API_MODELS:
        if placeholder in extended_placeholders:
            continue
        name = placeholder.__name__
        model = _gen_model(placeholder, name)
        setattr(module, name, model)
        namespace[name] = model
        concrete_models[placeholder] = model

    # resolve the `ForwardRef`s against our overriden stack
    for placeholder in _OPEN_API_MODELS:
        model = concrete_models[placeholder]
        _recursive_update_forward_refs(model, namespace)

    # helping hack for functions which depend on forward refs
    for func in _DEPENDENT_FUNCTIONS:
        func._namespace = namespace
