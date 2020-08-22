import sys
from typing import Dict

from pydantic import Field, root_validator, validator

from openapi_orm.base import (
    BaseModel,
    Operation as BaseOperation,
    install_models,
)


class BacklinkChain(BaseModel):
    value: str


class OperationBase(BaseOperation):
    backlinks: Dict[str, BacklinkChain] = Field({}, alias="x-apigraph-backlinks")
    other: int = 3

    def method(self):
        return self.other

    @validator("other")
    def check_other(cls, v):
        assert v > 0
        return v

    @root_validator
    def check_all_base(cls, values):
        if "extra" in values and "other" in values:
            assert values["extra"] > values["other"]
        return values


class Operation(OperationBase):
    extra: int = 11
    max_extra: int = 100

    def method(self):
        val = super().method()
        return val + self.extra

    @validator("extra")
    def check_extra(cls, v):
        assert v > 10
        return v

    @root_validator
    def check_all(cls, values):
        if "extra" in values and "max_extra" in values:
            assert values["extra"] <= values["max_extra"]
        return values


install_models(sys.modules[__name__], Operation)
