import functools


def _get_distribution(original_func, dist):
    if dist == "setools":
        dist = "android-setools"
    return original_func(dist)


try:
    import pkg_resources

    pkg_resources.get_distribution = functools.partial(
        _get_distribution,
        pkg_resources.get_distribution,
    )  # type: ignore
except ImportError:  # pragma: no cover
    pass
