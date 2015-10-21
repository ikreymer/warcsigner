Warc-Signer 0.3.0
=================

.. image:: https://travis-ci.org/ikreymer/warcsigner.svg?branch=master
  :target: https://travis-ci.org/ikreymer/warcsigner

.. image:: https://coveralls.io/repos/ikreymer/warcsigner/badge.svg
  :target: https://coveralls.io/r/ikreymer/warcsigner


Tools to add and a verify a cryptographic signature to WARC (or any gzip-chunked) files

This package provides complemetary ``warc-sign`` tool which signs WARC(s) with an RSA signature and 
``warc-verify`` which verifies that the WARC(s) have been signed.

Usage
------

Install with: ``python setup.py install``

Tests can be run with: ``python setup.py test``

To sign a warc:

``warc-sign privatekey.pem my-warc-file.warc.gz``

To verify that a warc has been signed:

``warc-verify publickey.pem my-warc-file.warc.gz``


API Usage
~~~~~~~~~

warcsigner can be used from other scripts.
To sign a warc:

::

  from warcsigner.warcsigner import RSASigner
  
  signer = RSASigner(private_key_file='privatekey.pem')
  
  if signer.sign('my-warc-file.warc.gz'):
      # warc signed successfully
  

or to verify:

::

  from warcsigner.warcsigner import RSASigner
  
  signer = RSASigner(public_key_file='publickey.pem')
  
  if signer.verify('my-warc-file.warc.gz'):
      # signature verified
  else:
      # signature not found/invalid


the ``sign`` and ``verify`` methods can take either a filename string or a file-like 
stream object (an object with a ``read`` method)

Additionally, upon verification, the signature can be removed:

::

  if signer.verify('my-warc-file.warc.gz', remove=True):
      # signature verified and removed

  assert signer.verify('my-warc-file.warc.gz') == False

If the first verify succeeds, the signature will be removed and file truncated
to its previous pre-signature size. (The file is unaltered if the verification fails).
This may be useful if planning to append to the WARC and then resigning it.

Streaming and ``seek()``
~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to use a file-like object which supports a ``read()`` instead of a filename.

When a WARC is signed, the signature is appended to the end of the file.

When verifying a file, the ``seek()`` may be used to determine the file size and the position of the signature.
However, if a ``size=`` param is added to ``verify`` or ``verify_stream`` calls, no seek() calls are made during
the verification and the file-like object is consumed linearly. This is specially useful
when streaming a file from a remote location and ``seek()`` is not available. 
The total file size must be provided, though.


Public/Private keys are expected to be in .PEM format
See the `python-rsa formats doc <http://stuvel.eu/files/python-rsa-doc/compatibility.html>`_ for more information
on supported key formats.

Original Stream
~~~~~~~~~~~~~~~

In certain situations, it may be useful to return the original, unsigned stream from a signed stream.
``signer.get_unsigned_stream(stream, size)`` will return a wrapper for `stream` which will not include the signature (if present). This is useful if concatenating WARCs without including a signature (and empty record) for each one.


How it works
------------

The `python-rsa <http://stuvel.eu/rsa>`_ library is used to sign and verify the signature.

The signature is stored in an extra gzip chunk containing no data but using `custom extra field <http://www.gzip.org/zlib/rfc-gzip.html#extra>`_ 
to store the signature. This allows the verify tool to quickly access the signature by checking a fixed offset from the end of the WARC.

When decompressing gzip chunks, there should be no detectable difference as most gzip tools ignore the extra gzip header.

While this is designed for compressed WARCs, this can be used for any format consisting of concatenated gzip chunks, ARC files, etc...

Note: since the signature is a gzip block, it makes less sense for uncompressed / plain text files.
