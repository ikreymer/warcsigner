import struct
import time
import io
import gzip

MAGIC_HEADER = '\037\213\010'
FLAGS = '\004'
XFL_OS = '\000\003'
EMPTY_DATA = '\003\000'


#=================================================================
class LengthMetadata:
    """
    Sample metadata which stores an 8-byte lengtg offset in the gzip header
    Could be used to store an offset

    This is used to test the gzip metadata write/read ops
    """
    def __init__(self, length=-1):
        self.length = length

    def id(self):
        return 'LN'

    def size(self):
        return 8

    def write(self, fh):
        write64(fh, long(self.length))

    def read(self, fh):
        self.length = long(read64(fh))


#=================================================================
def write_length_metadata(fh, length):
    r"""
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 1234)

    Verify block contents
    >>> buff.getvalue()
    '\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x03\x0c\x00LN\x08\x00\xd2\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    Verify block
    >>> len(buff.getvalue())
    34

    Verify actual block is empty
    >>> gzip.GzipFile(fileobj=buff).read(64)
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
    return struct.unpack("<H", input.read(2))[0]


def write32(fh, value):
    fh.write(struct.pack(b'<I', long(value)))

# currentl unused
def read32(input):  # pragma: no cover
    return struct.unpack("<I", input.read(4))[0]


def write64(fh, value):
    fh.write(struct.pack(b'<Q', long(value)))


def read64(input):
    return struct.unpack("<Q", input.read(8))[0]


#=================================================================
def read_length_metadata(fh):
    """
    write and read a length
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 1234)
    >>> read_length_metadata(buff)
    1234L

    write and read 0
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 0)
    >>> read_length_metadata(buff)
    0L

    write and read a full long
    >>> buff = io.BytesIO()
    >>> write_length_metadata(buff, 0x7fffffffffffffee)
    >>> hex(read_length_metadata(buff))
    '0x7fffffffffffffeeL'

    ensure gzip still consistent (empty)
    >>> b = buff.seek(0)
    >>> gzip.GzipFile(fileobj=buff).read()
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
if __name__ == "__main__":  # pragma: no cover
    import doctest
    doctest.testmod()
