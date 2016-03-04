from __future__ import absolute_import

import struct
import time
import io
import gzip

MAGIC_HEADER = b'\037\213\010'
FLAGS = b'\004'
XFL_OS = b'\000\003'
EMPTY_DATA = b'\003\000'


#=================================================================
class LengthMetadata(object):
    """
    Sample metadata which stores an 8-byte lengtg offset in the gzip header
    Could be used to store an offset

    This is used to test the gzip metadata write/read ops
    """
    def __init__(self, length=-1):
        self.length = length

    def id(self):
        return b'LN'

    def size(self):
        return 8

    def write(self, fh):
        write64(fh, int(self.length))

    def read(self, fh):
        self.length = int(read64(fh))


#=================================================================
def write_length_metadata(fh, length):
    r"""
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 1234)

    Verify block contents
    >>> _to_str(buff.getvalue())
    '\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03\x0c\x00LN\x08\x00\xd2\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    Verify block
    >>> len(buff.getvalue())
    34

    Verify actual block is empty
    >>> _to_str(gzip.GzipFile(fileobj=buff).read(64))
    ''
    """
    write_metadata(fh, LengthMetadata(length))


#=================================================================
def write_metadata(fh, metadata):
    fh.write(MAGIC_HEADER)
    fh.write(FLAGS)

    #timestamp
    write32(fh, 0)

    fh.write(XFL_OS)

    # total length
    write16(fh, metadata.size() + 4)
    fh.write(metadata.id()[:2])
    # length of metadata
    write16(fh, metadata.size())

    metadata.write(fh)

    # empty data
    fh.write(EMPTY_DATA)

    write32(fh, 0)
    write32(fh, 0)


#=================================================================
def size_of_header(metadata):
    return 26 + metadata.size()


#=================================================================
def write16(fh, value):
    fh.write(struct.pack(b'<H', int(value)))


def read16(input):
    return struct.unpack(b'<H', input.read(2))[0]


def write32(fh, value):
    fh.write(struct.pack(b'<I', int(value)))

# currentl unused
def read32(input):  # pragma: no cover
    return struct.unpack(b'<I', input.read(4))[0]


def write64(fh, value):
    fh.write(struct.pack(b'<Q', int(value)))


def read64(input):
    return struct.unpack(b'<Q', input.read(8))[0]


#=================================================================
def read_length_metadata(fh):
    """
    write and read a length
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 1234)
    >>> read_length_metadata(buff)
    1234

    write and read 0
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 0)
    >>> read_length_metadata(buff)
    0

    write and read a full int
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 0x7fffffffffffffee)
    >>> hex(read_length_metadata(buff))
    '0x7fffffffffffffee'

    ensure gzip still consistent (empty)
    >>> b = buff.seek(0)
    >>> _to_str(gzip.GzipFile(fileobj=buff).read())
    ''

    >>> read_length_metadata('')
    """

    len_metadata = LengthMetadata()
    if read_metadata(fh, len_metadata):
        return len_metadata.length
    else:
        return None


#=================================================================
def read_metadata(fh, metadata, seek=True):
    try:
        if seek:
            fh.seek(-14 - metadata.size(), 2)
        else:
            assert fh.read(len(MAGIC_HEADER)) == MAGIC_HEADER
            assert fh.read(len(FLAGS)) == FLAGS

            # ignore timestamp
            buff = read32(fh)

            assert fh.read(len(XFL_OS)) == XFL_OS

            # total length
            assert read16(fh) == (metadata.size() + 4)

        buff = fh.read(2)
        assert buff == metadata.id()[:2]

        buff = read16(fh)
        assert buff == metadata.size()

        metadata.read(fh)

        buff = fh.read(2)
        assert buff == EMPTY_DATA
        return True

    except AssertionError as ae:
        return False

    except Exception:
        return False


#=================================================================
def _to_str(val):
    import sys
    if sys.version_info >= (3,):  #pragma: no cover
        val = val.decode('latin-1')
    return val


#=================================================================
if __name__ == "__main__":  # pragma: no cover
    import doctest
    doctest.testmod()
