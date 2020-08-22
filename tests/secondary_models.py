import sys

from pydantic import validator

from openapi_orm.base import install_models

from .models import Operation as BaseOperation


class Operation(BaseOperation):

    secondary_extra: int = 13

    def method(self):
        val = super().method()
        return val + self.secondary_extra

    @validator("secondary_extra")
    def check_secondary_extra(cls, v):
        assert v > 11


install_models(sys.modules[__name__], Operation)
