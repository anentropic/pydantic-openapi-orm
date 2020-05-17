import re
from enum import Enum
from typing import Any, Dict, List, Optional, Union

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

# TODO: replace all Any with Optional[object] ?

# TODO: support extensions


def check_unique(val: List[Any]):
    """
    We can't do the `len(set(val))` trick because `val` may not
    be hashable...
    """
    seen = []
    for item in val:
        if item in seen:
            raise ValueError(f"values in list must be unique")
        seen.append(val)
    return val


class BaseModel(PydanticBaseModel):
    class Config:
        use_enum_values = True
        allow_mutation = False
        # TODO: auto CamelCase aliasing?


class Extensible:
    """
    Mark a model as allowing user-defined extensions, as per Open API spec

    (in Open API 3.0, any extension field names MUST be prefixed with `x-`
    ...apparently in Open API 3.1 this requirement will be removed)

    TODO: can we 'register' an extension model that delegates at runtime?
    or we should make all these models abstract and have a factory that
    constructs concrete OpenAPI3Document class with extensions baked in?
    """
    class Config:
        extra = "allow"


class Contact(Extensible, BaseModel):
    name: Optional[str]
    url: HttpUrl
    email: EmailStr


class License(Extensible, BaseModel):
    name: str
    url: Optional[HttpUrl]


class Info(Extensible, BaseModel):
    title: str
    description: Optional[str]
    termsOfService: Optional[str]
    contact: Optional[Contact]
    license: Optional[License]
    version: str


class ServerVariable(Extensible, BaseModel):
    enum: Optional[List[str]]
    default: str
    description: Optional[str]

    _check_enum = validator("enum", allow_reuse=True)(check_unique)


class Server(Extensible, BaseModel):
    url: str  # NO VALIDATION: MAY be relative, MAY have { } for var substitutions
    description: Optional[str]
    variables: Optional[Dict[str, ServerVariable]]


class ExternalDocumentation(Extensible, BaseModel):
    description: Optional[str]
    url: HttpUrl


class Discriminator(BaseModel):
    propertyName: str
    mapping: Optional[Dict[str, str]]


class XMLObj(Extensible, BaseModel):
    name: Optional[str]
    namespace: Optional[HttpUrl]
    prefix: Optional[str]
    attribute: bool = False
    wrapped: bool = False  # takes effect only when defined alongside type being array (outside the items)


# `Reference` must come first!
# (pydantic tries to instantiate members of Union type from L-R
# and takes the first oen that succeeds)
SchemaOrRef = Union["Reference", "Schema"]


class Schema(Extensible, BaseModel):
    """
    This class is a combination of JSON Schema rules:
    https://tools.ietf.org/html/draft-wright-json-schema-validation-00

    With some overrides and extra fields as defined by Open API here:
    https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#schemaObject
    """
    class Config:
        # hopefully this allows these fields to remain unset?
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
    allOf: Optional[List[SchemaOrRef]]
    oneOf: Optional[List[SchemaOrRef]]
    anyOf: Optional[List[SchemaOrRef]]
    not_: Optional[List[SchemaOrRef]]
    items: Optional[SchemaOrRef]
    properties: Optional[Dict[str, Union["PropertySchema", "Reference"]]]
    additionalProperties: Union[bool, SchemaOrRef] = True
    description: Optional[str]
    format_: Optional[str]
    default: Any

    nullable: bool = False
    discriminator: Optional[Discriminator]
    externalDocs: Optional[ExternalDocumentation]
    example: Any
    deprecated: bool = False

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
        if not any(key in values for key in {"oneOf", "anyOf", "allOf"}):
            raise ValueError(
                "`discriminator` is legal only when using one of the composite keywords `oneOf`, `anyOf`, `allOf`."
            )
        return values


class PropertySchema(Schema):
    readOnly: bool = False
    writeOnly: bool = False
    xml: Optional[XMLObj]


class Reference(BaseModel):
    ref: str = Field(..., alias="$ref")


class Example(Extensible, BaseModel):
    summary: Optional[str]
    description: Optional[str]
    value: Any
    externalValue: Optional[HttpUrl]

    @root_validator
    def check_value(cls, values):
        if values.get("value") and values.get("externalValue"):
            raise ValueError("`value` and `externalValue` are mutually-exclusive")
        return values


class Encoding(Extensible, BaseModel):
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


class MediaType(Extensible, BaseModel):
    class Config:
        fields = {
            "schema_": {"alias": "schema"}
        }

    schema_: Optional[SchemaOrRef]
    example: Any
    examples: Optional[Dict[str, Union[Reference, Example]]]
    encoding: Optional[Dict[str, Encoding]]

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


class Header(BaseModel):
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
    schema_: Optional[SchemaOrRef]
    example: Any
    examples: Optional[Dict[str, Union[Reference, Example]]]

    content: Optional[Dict[str, MediaType]]

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


class Parameter(Extensible, BaseModel):
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
    schema_: Optional[SchemaOrRef]
    example: Any
    examples: Optional[Dict[str, Union[Reference, Example]]]

    content: Optional[Dict[str, MediaType]]

    # x-link-src: JSON-Reference (where to get value from)
    # two options:
    # - extract: get value from this field in result
    # - reuse: use same value that was passed for this field in requestBody
    # ...could determine automatically depending on $ref path target?

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


class RequestBody(Extensible, BaseModel):
    description: Optional[str]
    content: Dict[str, MediaType]
    required: bool = False

    # x-link-sources: Dict[JSON-Pointer, JSON-Reference]


class Link(Extensible, BaseModel):
    operationRef: Optional[str]
    operationId: Optional[str]
    parameters: Optional[Dict[str, Any]]
    requestBody: Optional[Any]
    description: Optional[str]
    server: Optional[Server]

    @root_validator
    def check_operation(cls, values):
        if values.get("operationRef") and values.get("operationId"):
            raise ValueError(
                "`operationRef` and `operationId` are mutually-exclusive"
            )
        return values


class Response(Extensible, BaseModel):
    description: Optional[str]
    headers: Optional[Dict[str, Union[Reference, Header]]]
    content: Optional[Dict[str, MediaType]]
    links: Optional[Dict[str, Union[Reference, Link]]]


HTTP_STATUS_RE = re.compile(r"^[1-5][X0-9]{2}|default$")


Responses = Dict[str, Union[Reference, Response]]
# TODO: Extensible


def check_responses(val):
    for key in val:
        if not HTTP_STATUS_RE.match(key):
            raise ValueError(f"{key} is not a valid Response key")
    return val


Callback = Dict[str, 'PathItem']
# TODO: Extensible


SecurityRequirement = Dict[str, List[str]]
# Each name MUST correspond to a security scheme which is declared in the
# Security Schemes under the Components Object. (TODO)
# If the security scheme is of type "oauth2" or "openIdConnect", then the value
# is a list of scope names required for the execution. For other security
# scheme types, the array MUST be empty.


class Operation(Extensible, BaseModel):
    tags: Optional[List[str]]
    summary: Optional[str]
    description: Optional[str]
    externalDocs: Optional[ExternalDocumentation]
    operationId: Optional[str]
    parameters: Optional[List[Union[Reference, Parameter]]]
    requestBody: Optional[Union[Reference, RequestBody]]
    responses: Responses
    callbacks: Optional[Dict[str, Union[Reference, Callback]]]
    deprecated: bool = False
    security: Optional[List[SecurityRequirement]]
    servers: Optional[List[Server]]

    _check_parameters = validator("parameters", allow_reuse=True)(check_unique)
    _check_responses = validator("responses", allow_reuse=True)(check_responses)


class PathItem(Extensible, BaseModel):
    class Config:
        fields = {
            "ref": {"alias": "$ref"}
        }

    ref: Optional[str]
    summary: Optional[str]
    description: Optional[str]
    get: Optional[Operation]
    put: Optional[Operation]
    post: Optional[Operation]
    delete: Optional[Operation]
    options: Optional[Operation]
    head: Optional[Operation]
    patch: Optional[Operation]
    trace: Optional[Operation]

    # x-section-id: matching `x-sections` on the OpenAPI3Document

    # Apimatic instead adds top-level section (only) as a `tag` on the
    # `Operation` objects

    # an alternative might be to add leaf section as tags, then extend `Tag`
    # object with section ids


Paths = Dict[str, PathItem]
# TODO: Extensible


class _BaseOAuthFlow(Extensible, BaseModel):
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


OAuthFlow = Union[
    ImplicitOAuthFlow,
    AuthorizationCodeOAuthFlow,
    PasswordOAuthFlow,
    ClientCredentialsOAuthFlow,
]


class OAuthFlows(Extensible, BaseModel):
    implicit: Optional[OAuthFlow]
    password: Optional[OAuthFlow]
    clientCredentials: Optional[OAuthFlow]
    authorizationCode: Optional[OAuthFlow]


class Type_(str, Enum):
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"


class _BaseSecurityScheme(Extensible, BaseModel):
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
    flows: OAuthFlows


class OpenIDConnectSecurityScheme(_BaseSecurityScheme):
    openIdConnectUrl: HttpUrl


SecurityScheme = Union[
    APIKeySecurityScheme,
    HTTPSecurityScheme,
    OAuth2SecurityScheme,
    OpenIDConnectSecurityScheme,
]


class Components(Extensible, BaseModel):
    r"""
    TODO:
    All the fixed fields declared below are objects that MUST use keys that
    match the regular expression: ^[a-zA-Z0-9\.\-_]+$
    """
    schemas: Optional[Dict[str, SchemaOrRef]]
    responses: Optional[Dict[str, Union[Reference, Response]]]
    parameters: Optional[Dict[str, Union[Reference, Parameter]]]
    examples: Optional[Dict[str, Union[Reference, Example]]]
    requestBodies: Optional[Dict[str, Union[Reference, RequestBody]]]
    headers: Optional[Dict[str, Union[Reference, Header]]]
    securitySchemes: Optional[Dict[str, Union[Reference, SecurityScheme]]]
    links: Optional[Dict[str, Union[Reference, Link]]]
    callbacks: Optional[Dict[str, Union[Reference, Callback]]]


class Tag(Extensible, BaseModel):
    name: str
    description: Optional[str]
    externalDocs: Optional[ExternalDocumentation]


class OpenAPI3Document(Extensible, BaseModel):
    """
    See:
    https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md
    """
    openapi: constr(regex=r'\d+\.\d+\.\d+') = "3.0.2"
    info: Info
    servers: List[Server] = [Server(url="/")]
    paths: Paths
    components: Optional[Components]
    security: Optional[List[SecurityRequirement]]
    tags: Optional[List[Tag]]
    externalDocs: Optional[ExternalDocumentation]

    # x-sections: nested sections with id, title and description
