"""Application exceptions and stable process exit codes."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    USAGE = 2
    CONFIG = 3
    TRANSPORT = 4
    HTTP = 5
    VALIDATION = 6


class AnvilogicError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = ExitCode.ERROR


class ConfigError(AnvilogicError):
    exit_code = ExitCode.CONFIG


class TransportError(AnvilogicError):
    exit_code = ExitCode.TRANSPORT


class ResponseError(AnvilogicError):
    exit_code = ExitCode.HTTP


class ModelValidationError(AnvilogicError):
    exit_code = ExitCode.VALIDATION


class ModelCatalogError(ModelValidationError):
    """Raised when a model export is malformed or a model cannot be found."""
