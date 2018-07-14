#!/usr/bin/env python3

import glob
from setuptools import setup
import distutils.log as log
from distutils.core import Extension
from distutils.cmd import Command
from distutils.unixccompiler import UnixCCompiler
from setuptools.command.build_ext import build_ext
import subprocess
import sys
import os
from os.path import join
from contextlib import suppress
from Cython.Build import cythonize


class QtHelpCommand(Command):
    description = "Build Qt help files."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = ['qcollectiongenerator', 'qhc/apol.qhcp']
        self.announce("Building Qt help files", level=log.INFO)
        self.announce(' '.join(command), level=log.INFO)
        subprocess.check_call(command)
        self.announce("Moving Qt help files to setoolsgui/apol")
        os.rename('qhc/apol.qhc', 'setoolsgui/apol/apol.qhc')
        os.rename('qhc/apol.qch', 'setoolsgui/apol/apol.qch')


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

ext_py_mods = [Extension('setools.policyrep.libpolicyrep', ['setools/policyrep/libpolicyrep.pyx'],
                         include_dirs=include_dirs,
                         libraries=['selinux', 'sepol'],
                         library_dirs=lib_dirs,
                         runtime_library_dirs=lib_dirs,
                         define_macros=macros,
                         extra_compile_args=['-Werror', '-Wextra',
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
                                             '-Wno-unused-parameter',
                                             '-Wno-suggest-attribute=format',
                                             '-Wno-sign-compare',
                                             '-Wno-cast-qual',
                                             '-Wno-unreachable-code',
                                             '-Wno-implicit-fallthrough',
                                             '-Wno-cast-function-type',
                                             '-fno-exceptions'])]

setup(name='setools',
      version='4.2.0-beta',
      description='SELinux Policy tools.',
      author='Chris PeBenito',
      author_email='pebenito@ieee.org',
      url='https://github.com/SELinuxProject/setools',
      cmdclass={'build_qhc': QtHelpCommand},
      packages=['setools', 'setools.diff', 'setools.policyrep', 'setoolsgui', 'setoolsgui.apol'],
      scripts=['apol', 'sediff', 'seinfo', 'seinfoflow', 'sesearch', 'sedta'],
      data_files=[(join(sys.prefix, 'share/man/man1'), glob.glob("man/*.1"))],
      package_data={'': ['*.ui', '*.qhc', '*.qch'], 'setools': ['perm_map']},
      ext_modules=cythonize(ext_py_mods, include_path=['setools/policyrep'],
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
      )
