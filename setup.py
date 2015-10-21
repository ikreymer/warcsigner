#!/usr/bin/env python
# vim: set sw=4 et:

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import glob


long_description = open('README.rst').read()

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_suite = True

    def run_tests(self):
        import pytest
        import sys
        import os
        cmdline = ' --cov warcsigner'
        cmdline += ' -v --doctest-module ./warcsigner/ tests/'
        errcode = pytest.main(cmdline)
        sys.exit(errcode)

setup(
    name='warcsigner',
    version='0.3.0',
    url='https://github.com/ikreymer/warcsigner',
    author='Ilya Kreymer',
    author_email='ikreymer@gmail.com',
    description='Tools for signing and verifying WARC files',
    long_description=long_description,
    license='MIT',
    packages=find_packages(),
    provides=['warcsigner'],
    install_requires=['rsa'],
    tests_require=[
        'pytest',
        'pytest-cov',
       ],
    cmdclass={'test': PyTest},
    test_suite='',
    entry_points="""
        [console_scripts]
        warc-sign = warcsigner.warcsigner:sign_cli
        warc-verify = warcsigner.warcsigner:verify_cli
        """,
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Archiving',
        'Topic :: System :: Archiving :: Backup',
        'Topic :: Utilities',
    ])
