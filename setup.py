#!/usr/bin/env python

from setuptools import setup
from libapol import __version__

setup(name='setools',
	version=__version__,
	description='SELinux Policy tools.',
	author='Tresys Technology, LLC',
	author_email='setools@tresys.com',
	url='https://github.com/TresysTechnology/setools',
	packages=['libapol', 'libapol.policyrep'],
	scripts = ['seinfo', 'seinfoflow', 'sesearch', 'sedta'],
	data_files=[('/usr/share/setools', ['data/perm_map'])],
	test_suite='tests',
	license='GPLv2+, LGPLv2.1+',
	classifiers=[
		'Environment :: Console',
		'Intended Audience :: Information Technology',
		'Topic :: Security',
		'Topic :: Utilities',
		],
	)
