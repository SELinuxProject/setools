#!/usr/bin/env python

from setuptools import setup
from distutils.core import Extension

# setuptools/distutils does not support processing
# lex/yacc, so the source files are manually generated
# using the following commands:
# bison -y -d policy_parse.y -o policy_parse.c
# flex -o policy_scan.c policy_scan.l
ext_py_mods=[Extension('setools.policyrep._qpol',
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
                       include_dirs=['libqpol','libqpol/include'],
                       libraries=['bz2','selinux','sepol'],
                       extra_link_args=['-Wl,--version-script=libqpol/libqpol.map',
                                        '/usr/lib/libsepol.a'],
                       swig_opts=['-Ilibqpol/include'])]

setup(name='setools',
	version='4.0.0-alpha1',
	description='SELinux Policy tools.',
	author='Tresys Technology, LLC',
	author_email='setools@tresys.com',
	url='https://github.com/TresysTechnology/setools',
	packages=['setools', 'setools.policyrep'],
	scripts = ['seinfo', 'seinfoflow', 'sesearch', 'sedta'],
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
