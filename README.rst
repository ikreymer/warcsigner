Warc-Signer 0.1.0
====================

.. image:: https://travis-ci.org/ikreymer/warcsigner.svg?branch=master
  :target: https://travis-ci.org/ikreymer/warcsigner

.. image:: https://coveralls.io/repos/ikreymer/warcsigner/badge.png
  :target: https://coveralls.io/r/ikreymer/warcsigner


Tools to add and a verify a cryptographic signature to WARC (or any gzip-chunked) files

This package provides complemetary ``warc-sign`` tool which signs WARC(s) with an RSA signature and 
``warc-verify`` which verifies that the WARC(s) have been signed.

Usage
------

Install with: ``python setup.py install``

Tests can be run with: ``python setup.py test``

To sign a warc:

``warc-sign privatekey.pem warc.warc.gz``

To verify that a warc has been signed:

``warc-verify publickey.pem warc.warc.gz``


Public/Private keys are expected to be in .PEM format


How it works
------------

The `python-rsa <http://stuvel.eu/rsa>`_ library is used to sign and verify the signature.

The signature is stored in an extra gzip chunk containing no data but using `custom extra field <http://www.gzip.org/zlib/rfc-gzip.html#extra>`_ 
to store the signature. This allows the verify tool to quickly access the signature by checking a fixed offset from the end of the warc.

When decompressing gzip chunks, there should be no detectable difference as most gzip tools ignore the extra gzip header.

While this is designed for compressed WARCs, this can be used for any format consisting of concatenated gzip chunks, ARC files, etc...

Note: since the signature is a gzip block, it makes less sense for uncompressed / plain text files.
