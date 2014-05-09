from gzipmeta import write_metadata, read_metadata, size_of_header

import rsa
import math
import sys
import os

from argparse import ArgumentParser


#=================================================================
def numbits(x):
    """
    Convert a int/long to how many bits are necessary to store
    this number
    """
    return int(math.log(x, 2) / 8) + 1


#=================================================================
class RSAMetadata(object):
    """
    Custom metadata which represents an RSA signature
    Can be created with a known signature or known size of
    signature to be read
    """
    def __init__(self, signature='', size=0):
        self.signature = signature
        self._size = size

    def id(self):
        """
        uniq two-byte signature
        """
        return 'RS'

    def size(self):
        """
        If signature is set, return its length, otherwise
        use specified length
        """
        if self.signature:
            return len(self.signature)
        else:
            return self._size

    def write(self, fh):
        fh.write(self.signature)

    def read(self, fh):
        self.signature = fh.read(self.size())


#=================================================================
class LimitReader(object):
    """
    A simple reader which will not read more than specified limit
    """

    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit

    def read(self, length):
        length = min(length, self.limit)
        if length == 0:
            return ''

        buff = self.stream.read(length)
        self.limit -= len(buff)
        return buff


#=================================================================
class RSASigner(object):
    """ sign or verify an existing signature, appending it as metadata
    in an empty gzip record.
    - private key file should be specified for signing
    - public key file should be specified for verification
    """
    def __init__(self, private_key_file=None, public_key_file=None):
        if private_key_file:
            with open(private_key_file) as priv_fh:
                priv_data = priv_fh.read()
            self.priv_key = rsa.PrivateKey.load_pkcs1(priv_data)
        else:
            self.priv_key = None

        if public_key_file:
            with open(public_key_file) as pub_fh:
                pub_data = pub_fh.read()
            self.pub_key = rsa.PublicKey.load_pkcs1(pub_data)
        else:
            self.pub_key = None

    def sign(self, file_):
        if hasattr(file_, 'read'):
            return self.sign_stream(file_)
        else:
            if not os.path.isfile(file_):
                return False

            with open(file_, 'a+') as fh:
                return self.sign_stream(fh)

    def sign_stream(self, fh):
        fh.seek(0)
        signature = rsa.sign(fh, self.priv_key, 'SHA-1')

        rsa_meta = RSAMetadata(signature)

        write_metadata(fh, rsa_meta)

        fh.flush()
        return True

    def verify(self, file_, remove=False):
        if hasattr(file_, 'read'):
            return self.verify_stream(file_, remove)
        else:
            if not os.path.isfile(file_):
                return False

            mod = 'r' if not remove else 'a+'

            with open(file_, mod) as fh:
                return self.verify_stream(fh, remove)

    def verify_stream(self, fh, remove=False):
        size = numbits(self.pub_key.n)

        rsa_meta = RSAMetadata(size=size)
        sig_header = size_of_header(rsa_meta)

        try:
            fh.seek(-sig_header, 2)
        except IOError:
            return False

        if not read_metadata(fh, rsa_meta):
            return False

        fh.seek(0, 2)
        total_len = fh.tell() - sig_header

        fh.seek(0)
        lim = LimitReader(fh, total_len)
        try:
            result = rsa.verify(lim, rsa_meta.signature, self.pub_key)
        except rsa.pkcs1.VerificationError:
            return False

        if result and remove:
            fh.truncate(total_len)

        return result


#=================================================================
def sign_cli(args=None):
    parser = ArgumentParser(description='sign warcs(s) with given private key')

    parser.add_argument('private_key',
                        help='a privatekey.pem file in PEM format')

    parser.add_argument('inputs', nargs='+',
                        help='one or more files to sign')

    cmd = parser.parse_args(args=args)

    signer = RSASigner(private_key_file=cmd.private_key)

    errs = False

    for input_ in cmd.inputs:
        res = signer.sign(input_)

        if res:
            print 'Signed ', input_
        else:
            print 'NOT SIGNED'
            errs = True

    return 0 if not errs else 1


#=================================================================
def verify_cli(args=None):
    parser = ArgumentParser(description='verify warcs with given public key')

    parser.add_argument('public_key',
                        help='a public_key.pem file in PEM format')

    parser.add_argument('inputs', nargs='+',
                        help='one or more files to verify')

    cmd = parser.parse_args(args=args)

    signer = RSASigner(public_key_file=cmd.public_key)

    errs = False

    for input_ in cmd.inputs:
        res = signer.verify(input_)

        if res:
            print 'Verified ', input_
        else:
            print 'NOT VERIFIED'
            errs = True

    return 0 if not errs else 1
