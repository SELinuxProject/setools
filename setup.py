#!/usr/bin/env python

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


class QtHelpCommand(Command):
    description = "Build Qt help files."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = ['qcollectiongenerator', 'apol.qhcp', '-o', 'apol.qhc']
        self.announce("Building Qt help files", level=log.INFO)
        self.announce(' '.join(command), level=log.INFO)
        pwd = os.getcwd()
        os.chdir("./qhc")
        subprocess.check_call(command)
        os.chdir(pwd)


class YaccCommand(Command):
    description = "Build yacc parsers."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = ['bison', '-y', '-d', 'libqpol/policy_parse.y',
                   '-o', 'libqpol/policy_parse.c']
        self.announce("Generating parser", level=log.INFO)
        self.announce(' '.join(command), level=log.INFO)
        subprocess.check_call(command)


class LexCommand(Command):
    description = "Build lex scanners."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = [
            'flex', '-o', 'libqpol/policy_scan.c', 'libqpol/policy_scan.l']
        self.announce("Generating scanner", level=log.INFO)
        self.announce(' '.join(command), level=log.INFO)
        subprocess.check_call(command)


class BuildExtCommand(build_ext):

    def run(self):
        self.run_command('build_yacc')
        self.run_command('build_lex')
        build_ext.run(self)


try:
    static_sepol = os.environ['SEPOL']
except KeyError:
    # try to find libsepol.a. The find_library_file function
    # chooses dynamic libraries over static ones, so
    # this assumes that the static lib is in the same directory
    # as the dynamic lib.
    dynamic_sepol = UnixCCompiler().find_library_file(['.', '/usr/lib64', '/usr/lib'], 'sepol')
    static_sepol = dynamic_sepol.replace(".so", ".a")

if sys.platform.startswith('darwin'):
    macros=[('DARWIN',1)]
else:
    macros=[]

ext_py_mods = [Extension('setools.policyrep._qpol',
                         ['setools/policyrep/qpol.i',
                          'libqpol/avrule_query.c',
                          'libqpol/bool_query.c',
                          'libqpol/bounds_query.c',
                          'libqpol/class_perm_query.c',
                          'libqpol/cond_query.c',
                          'libqpol/constraint_query.c',
                          'libqpol/context_query.c',
                          'libqpol/default_object_query.c',
                          'libqpol/expand.c',
                          'libqpol/fs_use_query.c',
                          'libqpol/ftrule_query.c',
                          'libqpol/genfscon_query.c',
                          'libqpol/isid_query.c',
                          'libqpol/iterator.c',
                          'libqpol/mls_query.c',
                          'libqpol/mlsrule_query.c',
                          'libqpol/module.c',
                          'libqpol/module_compiler.c',
                          'libqpol/netifcon_query.c',
                          'libqpol/nodecon_query.c',
                          'libqpol/permissive_query.c',
                          'libqpol/polcap_query.c',
                          'libqpol/policy.c',
                          'libqpol/policy_define.c',
                          'libqpol/policy_extend.c',
                          'libqpol/portcon_query.c',
                          'libqpol/queue.c',
                          'libqpol/rbacrule_query.c',
                          'libqpol/role_query.c',
                          'libqpol/syn_rule_query.c',
                          'libqpol/terule_query.c',
                          'libqpol/type_query.c',
                          'libqpol/user_query.c',
                          'libqpol/util.c',
                          'libqpol/policy_parse.c',
                          'libqpol/policy_scan.c',
                          'libqpol/xen_query.c'],
                         include_dirs=['libqpol', 'libqpol/include', 'include'],
                         libraries=['bz2'],
                         extra_compile_args=['-Werror', '-Wextra',
                                             '-Waggregate-return',
                                             '-Wcast-align',
                                             '-Wfloat-equal',
                                             '-Wformat', '-Wformat=2',
                                             '-Winit-self', '-Winline',
                                             '-Wmissing-format-attribute',
                                             '-Wmissing-include-dirs',
                                             '-Wnested-externs',
                                             '-Wold-style-definition',
                                             '-Wpointer-arith',
                                             '-Wredundant-decls',
                                             '-Wstrict-prototypes',
                                             '-Wunknown-pragmas',
                                             '-Wwrite-strings',
                                             '-Wno-missing-field-initializers', # SWIG 3.0.2 generates partially-initialized structs
                                             '-Wno-unused-parameter', # SWIG generates functions with unused parameters
                                             '-Wno-cast-qual', # libsepol uses const-to-nonconst casts
                                             '-Wno-shadow', # SWIG generates shadow variables
                                             '-fno-exceptions'],
                         swig_opts=['-Ilibqpol/include'],
                         define_macros=macros,
                         extra_objects=[static_sepol])]

setup(name='setools',
      version='4.0.0-beta',
      description='SELinux Policy tools.',
      author='Tresys Technology, LLC',
      author_email='setools@tresys.com',
      url='https://github.com/TresysTechnology/setools',
      cmdclass={'build_yacc': YaccCommand,
                'build_lex': LexCommand,
                'build_ext': BuildExtCommand,
                'build_qhc': QtHelpCommand},
      packages=['setools', 'setools.diff', 'setools.policyrep', 'setoolsgui', 'setoolsgui.apol'],
      scripts=['apol', 'sediff', 'seinfo', 'seinfoflow', 'sesearch', 'sedta'],
      data_files=[(join(sys.prefix, 'share/man/man1'), glob.glob("man/*.1") ),
                  (join(sys.prefix, 'share/setools'), glob.glob("data/*.ui") +
                                                      ["data/perm_map", "qhc/apol.qhc"] ),
                  (join(sys.prefix, 'share/setools/icons'), glob.glob("data/icons/*.png"))],
      ext_modules=ext_py_mods,
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
