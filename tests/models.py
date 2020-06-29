import sys
from typing import Dict, Optional

from pydantic import Field, root_validator

from openapi_orm.base import (
    BaseModel,
    Operation as BaseOperation,
    install_models,
)


class RedundantSpecifiers(Exception):
    pass


class MissingRequiredField(Exception):
    pass


class BacklinkOperation(BaseModel):
    operationId: Optional[str]
    operationRef: Optional[str]
    response: Optional[str]
    responseRef: Optional[str]

    @root_validator
    def check_field_groups(cls, values):
        if values.get("responseRef"):
            if any(values.get(key)
                   for key in {"operationId", "operationRef", "response"}):
                raise RedundantSpecifiers(
                    "`responseRef` found: do not supply other specifiers."
                )
        elif values.get("operationId"):
            if values.get("operationRef"):
                raise RedundantSpecifiers(
                    "`operationId` found: do not supply an `operationRef`."
                )
            if not values.get("response"):
                raise MissingRequiredField(
                    "`response` is required when `operationId` is specified."
                )
        elif values.get("operationRef"):
            if values.get("operationId"):
                raise RedundantSpecifiers(
                    "`operationRef` found: do not supply an `operationId`."
                )
            if not values.get("response"):
                raise MissingRequiredField(
                    "`response` is required when `operationRef` is specified."
                )
        else:
            raise MissingRequiredField(
                "One of: `responseRef`, `operationId`+`response` or "
                "`operationRef`+`response` is required."
            )
        return values


class BacklinkParameter(BaseModel):
    class Config(BaseModel.Config):
        allow_population_by_field_name = True  # because `from` is a keyword

    from_: str = Field(..., alias="from")
    select: str


class BacklinkChain(BaseModel):
    operations: Dict[str, BacklinkOperation]
    parameters: Dict[str, BacklinkParameter] = Field(default_factory=dict)
    requestBody: Optional[BacklinkParameter]
    requestBodyParameters: Dict[str, BacklinkParameter] = Field(default_factory=dict)


class OperationBase(BaseOperation):
    backlinks: Dict[str, BacklinkChain] = Field({}, alias="x-apigraph-backlinks")

    def method(self):
        return 3


class Operation(OperationBase):
    extra: int = 2

    def method(self):
        val = super().method()
        return val + self.extra


install_models(sys.modules[__name__], Operation)
