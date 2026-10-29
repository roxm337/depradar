"""Refusals a use case reports; each interface maps them to its own responses."""


class ApplicationError(Exception):
    """Base class. The message is safe to show to the caller."""


class NotFound(ApplicationError):
    pass


class Conflict(ApplicationError):
    """The request conflicts with the current state."""


class Invalid(ApplicationError):
    """The request is well formed, but its values are not acceptable."""


class Forbidden(ApplicationError):
    pass


class Unauthorized(ApplicationError):
    pass


class RateLimited(ApplicationError):
    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class Unavailable(ApplicationError):
    """A required service or configuration is missing."""


class UpstreamFailed(ApplicationError):
    """An external provider refused or failed the request."""
