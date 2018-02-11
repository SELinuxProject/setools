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


base_lib_dirs = ['.', '/usr/lib64', '/usr/lib', '/usr/local/lib']
include_dirs = ['libqpol', 'libqpol/include']

with suppress(KeyError):
    base_lib_dirs.insert(0, os.environ["SEPOL_SRC"] + "/src")
    include_dirs.append(os.environ["SEPOL_SRC"] + "/include")

try:
    static_sepol = os.environ['SEPOL']
except KeyError:
    # try to find libsepol.a. The find_library_file function
    # chooses dynamic libraries over static ones, so
    # this assumes that the static lib is in the same directory
    # as the dynamic lib.
    dynamic_sepol = UnixCCompiler().find_library_file(base_lib_dirs, 'sepol')

    if dynamic_sepol is None:
        print('Unable to find a libsepol.so on your system!')
        print("Looked in the following directories:\n{}".format("\n".join(base_lib_dirs)))
        print('Please set the SEPOL or SEPOL_SRC environment variables. Exiting.')
        exit(1)

    static_sepol = dynamic_sepol.replace(".so", ".a")

if sys.platform.startswith('darwin'):
    macros=[('DARWIN',1)]
else:
    macros=[]

ext_py_mods = [Extension('setools.policyrep.libpolicyrep',
                         ['setools/policyrep/libpolicyrep.pyx',
                          'libqpol/avrule_query.c',
                          'libqpol/bounds_query.c',
                          'libqpol/class_perm_query.c',
                          'libqpol/cond_query.c',
                          'libqpol/constraint_query.c',
                          'libqpol/context_query.c',
                          'libqpol/default_object_query.c',
                          'libqpol/ftrule_query.c',
                          'libqpol/iterator.c',
                          'libqpol/mlsrule_query.c',
                          'libqpol/policy.c',
                          'libqpol/policy_extend.c',
                          'libqpol/rbacrule_query.c',
                          'libqpol/terule_query.c'],
                         include_dirs=include_dirs,
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
                                             '-Wno-sign-compare', # Bison
                                             '-Wno-cast-qual', # libsepol uses const-to-nonconst casts
                                             '-Wno-unreachable-code', # Bison generates unreachable code
                                             '-fno-exceptions'],
                         define_macros=macros,
                         extra_objects=[static_sepol])]

setup(name='setools',
      version='4.2-dev',
      description='SELinux Policy tools.',
      author='Tresys Technology, LLC',
      author_email='setools@tresys.com',
      url='https://github.com/TresysTechnology/setools',
      cmdclass={'build_qhc': QtHelpCommand},
      packages=['setools', 'setools.diff', 'setools.policyrep', 'setoolsgui', 'setoolsgui.apol'],
      scripts=['apol', 'sediff', 'seinfo', 'seinfoflow', 'sesearch', 'sedta'],
      data_files=[(join(sys.prefix, 'share/man/man1'), glob.glob("man/*.1"))],
      package_data={'': ['*.ui', '*.qhc', '*.qch'], 'setools': ['perm_map']},
      ext_modules=cythonize(ext_py_mods, include_path=['setools/policyrep']),
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
