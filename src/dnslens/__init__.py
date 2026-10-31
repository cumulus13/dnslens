"""dnslens - cross-platform DNS toolkit for developers and DevOps."""
try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("dnslens")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.0.0+local"
except ImportError:  # pragma: no cover
    __version__ = "0.0.0+local"

__all__ = ["__version__"]
