import sys

from openapi_orm.base import install_models


install_models(sys.modules[__name__])
