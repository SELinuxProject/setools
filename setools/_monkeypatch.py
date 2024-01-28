import functools
import os
from contextlib import contextmanager


def _get_distribution(original_func, dist):
    if dist == 'setools':
        dist = 'android-setools'
    return original_func(dist)


@contextmanager
def _cd(path):
    old_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old_dir)


try:
    import pkg_resources
    pkg_resources.get_distribution = functools.partial(
        _get_distribution,
        pkg_resources.get_distribution,
    )  # type: ignore
except ImportError:  # pragma: no cover
    pass


package_dir = os.path.realpath(os.path.dirname(__file__))
with _cd(package_dir):
    from . import policyrep
