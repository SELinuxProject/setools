#!/usr/bin/env python3

import glob
from setuptools import Extension, setup
import sys
import os
from os.path import join
from contextlib import suppress
from Cython.Build import cythonize
import os.path


# Library linkage
lib_dirs = ['.', '/usr/lib64', '/usr/lib', '/usr/local/lib']
include_dirs = []

with suppress(KeyError):
    userspace_src = os.environ["USERSPACE_SRC"]
    include_dirs.insert(0, userspace_src + "/libsepol/include")
    include_dirs.insert(1, userspace_src + "/libselinux/include")
    lib_dirs.insert(0, userspace_src + "/libsepol/src")
    lib_dirs.insert(1, userspace_src + "/libselinux/src")

if sys.platform.startswith('darwin'):
    macros=[('DARWIN',1)]
else:
    macros=[]

# Code coverage.  Enable this to get coverage in the cython code.
enable_coverage = bool(os.environ.get("SETOOLS_COVERAGE", False))
if enable_coverage:
    macros.append(("CYTHON_TRACE", 1))

cython_annotate = bool(os.environ.get("SETOOLS_ANNOTATE", False))

ext_py_mods = [Extension('setools.policyrep', ['setools/policyrep.pyx'],
                         include_dirs=include_dirs,
                         libraries=['selinux', 'sepol'],
                         library_dirs=lib_dirs,
                         define_macros=macros,
                         extra_compile_args=['-Wextra',
                                             '-Waggregate-return',
                                             '-Wfloat-equal',
                                             '-Wformat', '-Wformat=2',
                                             '-Winit-self',
                                             '-Wmissing-format-attribute',
                                             '-Wmissing-include-dirs',
                                             '-Wnested-externs',
                                             '-Wold-style-definition',
                                             '-Wpointer-arith',
                                             '-Wstrict-prototypes',
                                             '-Wunknown-pragmas',
                                             '-Wwrite-strings',
                                             '-fno-exceptions'])]

installed_data = [('share/man/man1', glob.glob("man/*.1"))]

linguas = ["ru"]

with suppress(KeyError):
    linguas = os.environ["LINGUAS"].split(" ")

for lang in linguas:
    if lang and os.path.exists(join("man", lang)):
        installed_data.append((join('share/man', lang, 'man1'), glob.glob(join("man", lang, "*.1"))))

setup(name='setools',
      version='4.6.0-dev',
      description='SELinux policy analysis tools.',
      author='Chris PeBenito',
      author_email='pebenito@ieee.org',
      url='https://github.com/SELinuxProject/setools',
      packages=['setools', 'setools.checker', 'setools.diff', 'setoolsgui', 'setoolsgui.widgets',
                'setoolsgui.widgets.criteria', 'setoolsgui.widgets.details',
                'setoolsgui.widgets.models', 'setoolsgui.widgets.views'],
      scripts=['apol', 'sediff', 'seinfo', 'seinfoflow', 'sesearch', 'sedta', 'sechecker'],
      data_files=installed_data,
      package_data={'': ['*.css', '*.html'],
                    'setools': ['perm_map', 'policyrep.pyi', 'py.typed']},
      ext_modules=cythonize(ext_py_mods, include_path=['setools/policyrep'],
                            annotate=cython_annotate,
                            compiler_directives={"language_level": 3,
                                                 "c_string_type": "str",
                                                 "c_string_encoding": "ascii",
                                                 "linetrace": enable_coverage}),
      test_suite='tests',
      license='GPLv2+, LGPLv2.1+',
      classifiers=[
          'Environment :: Console',
          'Environment :: X11 Applications :: Qt',
          'Intended Audience :: Information Technology',
          'Topic :: Security',
          'Topic :: Utilities',
      ],
      keywords='SELinux SETools policy analysis tools seinfo sesearch sediff sedta seinfoflow apol',
      python_requires='>=3.10',
      # setup also requires libsepol and libselinux
      # C libraries and headers to compile.
      setup_requires=['setuptools', 'Cython>=0.29.14'],
      install_requires=['setuptools'],
      extras_require={
          "analysis": ["networkx>=2.6", "pygraphviz"],
          "test": "tox"
      }
      )
