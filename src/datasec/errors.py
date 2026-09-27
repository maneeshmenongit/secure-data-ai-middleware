"""Exceptions raised by the DataSec core."""


class DataSecError(Exception):
    """Base class for every DataSec failure."""


class UnsupportedPayload(DataSecError):
    """A payload contains a value type the redactor cannot inspect."""


class RedactionError(DataSecError):
    """Redaction could not produce a safe payload."""
