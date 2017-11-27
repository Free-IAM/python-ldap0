#!/bin/sh

python setup.py clean
rm -r MANIFEST dist/ldap0* build/* *.egg-info .tox docs/.build/*
rm _libldap0.so ldap0/*.py? ldap0/*/*.py? tests/*.py? *.py?
find -name __pycache__ | xargs -n1 -iname rm -r name
rm -r slapdtest-[0-9]
