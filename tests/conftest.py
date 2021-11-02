"""
Configuration for pytest
"""


def pytest_make_parametrize_id(config, val):
    """
    Return a user-friendly string representation of the given `val` that will be
    used by @pytest.mark.parametrize calls, or None if the hook doesn’t know
    about val.
    """
    # pytest's API; pylint: disable=unused-argument
    if getattr(val, "__module__", val.__class__.__module__).startswith("spartancoin"):
        return repr(val)
    return None
