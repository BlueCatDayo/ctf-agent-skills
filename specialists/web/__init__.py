"""Stage 7 web specialists - package registry.

Each module defines one :class:`Specialist` subclass.  ``WEB_SPECIALISTS``
is the ordered list used to populate the specialist router.
"""

from .api_analysis import JavaScriptApiSpecialist
from .authentication import AuthenticationSpecialist
from .file_inclusion import FileInclusionSpecialist
from .graphql import GraphQLSpecialist
from .jwt import JWTSpecialist
from .php import PHPSpecialist
from .race_condition import RaceConditionSpecialist
from .sql_injection import SQLInjectionSpecialist
from .ssti import SSTISpecialist
from .upload_analysis import UploadAnalysisSpecialist
from .websocket import WebSocketSpecialist

WEB_SPECIALISTS = [
    SQLInjectionSpecialist,
    AuthenticationSpecialist,
    JWTSpecialist,
    SSTISpecialist,
    FileInclusionSpecialist,
    JavaScriptApiSpecialist,
    UploadAnalysisSpecialist,
    GraphQLSpecialist,
    WebSocketSpecialist,
    RaceConditionSpecialist,
    PHPSpecialist,
]

__all__ = ["WEB_SPECIALISTS"]
