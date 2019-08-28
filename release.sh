#!/bin/bash

# Don't use uninitialized vars
set -o nounset
# After here exit on any error
set -e
# Set strict umask
umask 077

# remove all temporary stuff
./clean.sh

# first run the test suite isolated just to be sure
tox-3.7

# determine version numer
RELEASE=$(PYTHONPATH=ldap0 python3 -c 'from __about__ import __version__ ; print(__version__)')

echo "Will tag and publish ${RELEASE} now..."

# tag the git repo
git tag -s -m "release ${RELEASE}" "v${RELEASE}"

# build source distribution and push to PyPI
# (release defined in setup.cfg)
python3 setup.py release
