# SETools: Policy analysis tools for SELinux
https://github.com/TresysTechnology/setools/wiki

## Overview

This file describes SETools, developed by Tresys Technology.  SETools
is a collection of graphical tools, command-line tools, and libraries
designed to facilitate SELinux policy analysis.  Please consult the
KNOWN-BUGS file prior to reporting bugs.

## Installation

SETools uses the Python setuptools build system to build, and install.
As such it contains a setup.py script that will install the tools.

To run SETools, the following packages are required:
* Python 2.7 or 3.3+
* NetworkX 1.8+
* setuptools
* libselinux (Python bindings optional but recommended)
* libbz2

To build SETools, the following development packages are required, in
addition to the development packages from the above list:
* gcc
* bison
* flex
* libsepol 2.4+
* SWIG 2.0.12+ or 3.0+

To run SETools unit tests, the following packages are required, in
addition to the above dependencies:
* mock (on Python 2.7 only)
* tox (optional)

### Building SETools

Unpack the official distribution or check out the git repository,
and perform the following at the root:
```
  $ python setup.py build
  $ python setup.py install
```
This will put the applications in /usr/bin, data files in /usr/share/setools,
and libraries in /usr/lib/pythonX.Y/site-packages/setools.

### Installation Options

Please see `python setup.py --help` or `python setup.py install --help`
for up-to-date information on build and install options, respectively.

### Unit Tests

One goal for SETools is to provide confidence in the validity of the
output for the tools.  The unit tests for SETools can be run with
the following command
```
  $ python setup.py test
```

## Features

SETools encompasses a number of tools, both graphical and command
line, and libraries.  Many of the programs have help files accessible
during runtime.

### Graphical tools

TBD

### Command-line tools

Some tools in the SETools suite may be run in a terminal
environment.

Tool Name  | Use
---------- | -------------------------------------------
sedta      | Perform domain transition analyses
seinfo     | List policy components.
seinfoflow | Perform information flow analyses.
sesearch   | Search rules (allow, type_transition, etc.)

### Analysis Libraries

The SETools libraries are available for use in third-party
applications.  Although this is not officially supported, we will
do our best to maintain API stability.

### Obtaining SETools

Official releases of SETools may be freely downloaded from:

https://github.com/TresysTechnology/setools/releases

SETools source code is maintained within a GitHub repository.
From the command line do:
```
  $ git clone https://github.com/TresysTechnology/setools.git
```
You may also browse the GitHub repository at
https://github.com/TresysTechnology/setools.

SETools included in most Linux distributions which support
SELinux, such as Fedora, Red Hat Enterprise Linux, Gentoo,
and Debian.

### Reporting bugs

Bugs can be reported in the SETools GitHub issues tracker:

https://github.com/TresysTechnology/setools/issues

### Copyright license

The intent is to allow free use of this source code.  All programs'
source files are copyright protected and freely distributed under the
GNU General Public License (see COPYING.GPL).  All library source
files are copyright under the GNU Lesser General Public License (see
COPYING.LGPL).  All files distributed with this package indicate the
appropriate license to use.  Absolutely no warranty is provided or implied.
