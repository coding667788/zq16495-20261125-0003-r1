class KeychronicleError(Exception):
    """Base error with a stable CLI-facing message."""


class BundleError(KeychronicleError):
    """The bundle is missing required data or violates its schema."""


class TimeFormatError(KeychronicleError):
    """A timestamp is not ISO-8601."""
