from gzipmeta import write_metadata, read_metadata, size_of_header

import rsa
import math
import sys
import os

from argparse import ArgumentParser
from io import BytesIO

from rsa.pkcs1 import VerificationError


DEFAULT_HASH_TYPE = 'SHA-1'


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

    def read(self, length=8192):
        length = min(length, self.limit)
        if length == 0:
            return ''

        buff = self.stream.read(length)
        self.limit -= len(buff)
        return buff


#=================================================================
class UnsignedStream(LimitReader):
    def __init__(self, stream, unsigned_len, rsa_meta):
        super(UnsignedStream, self).__init__(stream, unsigned_len)
        self.rsa_meta = rsa_meta

    def read(self, length=8192):
        buff = super(UnsignedStream, self).read(length)
        if buff:
            return buff

        # check that remainder is actually a signature
        buff = self.stream.read()
        if not buff:
            return ''

        # if not, just return buff
        if not read_metadata(BytesIO(buff), self.rsa_meta, seek=False):
            return buff

        return ''


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

    def sign(self, file_, hash_type=DEFAULT_HASH_TYPE):
        if hasattr(file_, 'read'):
            return self.sign_stream(file_, hash_type)
        else:
            if not os.path.isfile(file_):
                return False

            with open(file_, 'a+') as fh:
                return self.sign_stream(fh, hash_type)

    def sign_stream(self, fh, hash_type):
        fh.seek(0)
        signature = rsa.sign(fh, self.priv_key, hash_type)

        rsa_meta = RSAMetadata(signature)

        write_metadata(fh, rsa_meta)

        fh.flush()
        return True

    def verify(self, file_, size=None, remove=False,
               hash_type=DEFAULT_HASH_TYPE):
        if hasattr(file_, 'read'):
            if size is not None:
                return self.verify_stream_data(file_, size, hash_type)
            else:
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
        except VerificationError:
            return False

        if result and remove:
            fh.truncate(total_len)

        return result

    def verify_stream_data(self, fh, total_len, hash_type):
        size = numbits(self.pub_key.n)

        rsa_meta = RSAMetadata(size=size)
        sig_header = size_of_header(rsa_meta)
        total_len -= sig_header

        lim = LimitReader(fh, total_len)

        def read_sig():
            if not read_metadata(fh, rsa_meta, seek=False):
                return False

            return rsa_meta.signature

        try:
            result = _rsa_streaming_verify(lim, read_sig,
                                           self.pub_key, hash_type)
        except VerificationError:
            return False

        return result

    def get_unsigned_stream(self, fh, total_len, hash_type=DEFAULT_HASH_TYPE):
        """ Return a stream that truncates the signature, if present
        """
        size = numbits(self.pub_key.n)

        rsa_meta = RSAMetadata(size=size)
        sig_header = size_of_header(rsa_meta)
        total_len -= sig_header

        return UnsignedStream(fh, total_len, rsa_meta)


#=================================================================
def _rsa_streaming_verify(fh, sig_func, pub_key, hash_type):

    # Compute hash first, using given type
    message_hash = rsa.pkcs1._hash(fh, hash_type)

    # Compute signature given sig_func(), presumably
    # reading rest of stream
    signature = sig_func()

    if not signature:
        raise VerificationError('Verification failed')

    # Below is copy of rest of rsa.verify() to check the signature
    # ------------------------------------------------------------
    blocksize = rsa.common.byte_size(pub_key.n)
    encrypted = rsa.transform.bytes2int(signature)
    decrypted = rsa.core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = rsa.transform.int2bytes(decrypted, blocksize)

    # If we can't find the signature  marker, verification failed.
    if clearsig[0:2] != rsa._compat.b('\x00\x01'):
        raise VerificationError('Verification failed')

    # Find the 00 separator between the padding and the payload
    try:
        sep_idx = clearsig.index(rsa._compat.b('\x00'), 2)
    except ValueError:  # pragma: no cover (part of rsa.verify())
        raise VerificationError('Verification failed')

    # Get the hash method and and signature
    (actual_hash_type, signature_hash) = (rsa.pkcs1.
        _find_method_hash(clearsig[sep_idx + 1:]))

    # Compare the real hash to the hash in the signature
    if message_hash != signature_hash or hash_type != actual_hash_type:
        raise VerificationError('Verification failed')

    # end rsa.verify() --------------------------------------------
    return True


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


    parser.add_argument('-r', '--remove', help='remove verification signature',
                        action='store_true')

    cmd = parser.parse_args(args=args)

    signer = RSASigner(public_key_file=cmd.public_key)

    errs = False

    for input_ in cmd.inputs:
        res = signer.verify(input_, remove=cmd.remove is not None)

        if res:
            print 'Verified ', input_
        else:
            print 'NOT VERIFIED'
            errs = True

    return 0 if not errs else 1
