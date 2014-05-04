from warcsigner.warcsigner import RSASigner, sign_cli, verify_cli
from pytest import raises

import shutil
import os


def abs_path(filename):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)

TEST_WARC = abs_path('test_warc.warc.gz')
TEMP_SIGNED_WARC = abs_path('test_warc.warc.gz.signed')
EMPTY_FILE = abs_path('empty.warc.gz')


PRIVATE_KEY = abs_path('test_private_key.pem')
PUBLIC_KEY = abs_path('test_public_key.pem')


class TestWarcSigner(object):
    def setup(self):
        self.signer = RSASigner(private_key_file=PRIVATE_KEY,
                                public_key_file=PUBLIC_KEY)

    def test_sign(self):
        shutil.copyfile(TEST_WARC, TEMP_SIGNED_WARC)
        assert self.signer.sign(TEMP_SIGNED_WARC) == True
        assert self.signer.verify(TEMP_SIGNED_WARC) == True

        # not signed
        assert self.signer.verify(TEST_WARC) == False
        os.remove(TEMP_SIGNED_WARC)

    def test_cli_sign(self):
        shutil.copyfile(TEST_WARC, TEMP_SIGNED_WARC)
        assert sign_cli([PRIVATE_KEY, TEMP_SIGNED_WARC]) == 0
        assert verify_cli([PUBLIC_KEY, TEMP_SIGNED_WARC]) == 0

        # not signed
        assert verify_cli([PUBLIC_KEY, TEST_WARC]) == 1
        os.remove(TEMP_SIGNED_WARC)

    def test_empty_sign(self):
        open(EMPTY_FILE, 'w').close()

        # not signed
        assert verify_cli([PUBLIC_KEY, EMPTY_FILE]) == 1

        # sign
        assert sign_cli([PRIVATE_KEY, EMPTY_FILE]) == 0

        # verify signed
        assert verify_cli([PUBLIC_KEY, EMPTY_FILE]) == 0

        os.remove(EMPTY_FILE)

        # non-existent file
        assert sign_cli([PRIVATE_KEY, EMPTY_FILE]) == 1
        assert verify_cli([PUBLIC_KEY, EMPTY_FILE]) == 1
