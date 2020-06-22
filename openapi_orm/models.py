import sys

from openapi_orm.base import install_modules


install_modules(sys.modules[__name__])
