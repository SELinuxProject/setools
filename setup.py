#!/usr/bin/env python

from setuptools import setup
import distutils.log as log
from distutils.core import Extension
from distutils.cmd import Command
from setuptools.command.build_ext import build_ext
import subprocess


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
                          'libqpol/policy_scan.c'],
                         include_dirs=['libqpol', 'libqpol/include'],
                         libraries=['bz2', 'selinux', 'sepol'],
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
                                             '-Wno-cast-qual', # libsepol/libselinux uses const-to-nonconst casts
                                             '-Wno-shadow', # SWIG generates shadow variables
                                             '-fno-exceptions'],
                         extra_link_args=['-Wl,--version-script=libqpol/libqpol.map',
                                          '/usr/lib/libsepol.a'],
                         swig_opts=['-Ilibqpol/include'])]

setup(name='setools',
      version='4.0.0-alpha1',
      description='SELinux Policy tools.',
      author='Tresys Technology, LLC',
      author_email='setools@tresys.com',
      url='https://github.com/TresysTechnology/setools',
      cmdclass={'build_yacc': YaccCommand,
                'build_lex': LexCommand,
                'build_ext': BuildExtCommand},
      packages=['setools', 'setools.policyrep'],
      scripts=['seinfo', 'seinfoflow', 'sesearch', 'sedta'],
      data_files=[('/usr/share/setools', ['data/perm_map'])],
      ext_modules=ext_py_mods,
      test_suite='tests',
      license='GPLv2+, LGPLv2.1+',
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: Information Technology',
          'Topic :: Security',
          'Topic :: Utilities',
      ],
      )
