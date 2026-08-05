"""Stage 7 binary exploitation specialists - package registry."""

from .buffer_overflow import BufferOverflowSpecialist
from .format_string import FormatStringSpecialist
from .pwntools_runner import PwntoolsRunnerSpecialist
from .ret2win import Ret2winSpecialist
from .rop_analysis import RopAnalysisSpecialist
from .triage import BinaryTriageSpecialist

BINARY_SPECIALISTS = [
    BinaryTriageSpecialist,
    BufferOverflowSpecialist,
    FormatStringSpecialist,
    Ret2winSpecialist,
    RopAnalysisSpecialist,
    PwntoolsRunnerSpecialist,
]

__all__ = ["BINARY_SPECIALISTS"]
