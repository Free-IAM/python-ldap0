#!/bin/sh

python setup.py clean
rm -r MANIFEST dist/* build/* Lib/*.egg-info .tox 
rm _libldap0.so ldap0/*.py? ldap0/*/*.py? tests/*.py? *.py?
