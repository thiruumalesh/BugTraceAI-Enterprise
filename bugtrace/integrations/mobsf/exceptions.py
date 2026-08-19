class MobSFError(Exception):
    """Base exception for MobSF integration."""


class MobSFConnectionError(MobSFError):
    """MobSF server could not be reached."""


class MobSFAPIError(MobSFError):
    """MobSF API returned an error."""
