from warcsigner.warcsigner import RSASigner, sign_cli, verify_cli
from pytest import raises

import shutil
import os
import tempfile


def abs_path(filename):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)

TEST_WARC = abs_path('test_warc.warc.gz')
TEMP_SIGNED_WARC = abs_path('test_warc.warc.gz.signed')
EMPTY_FILE = abs_path('empty.warc.gz')


PRIVATE_KEY = abs_path('test_private_key.pem')
PUBLIC_KEY = abs_path('test_public_key.pem')
PUBLIC_WRONG_KEY = abs_path('test_wrong_key.pem')


class TestWarcSigner(object):
    def setup(self):
        self.signer = RSASigner(private_key_file=PRIVATE_KEY,
                                public_key_file=PUBLIC_KEY)

    def test_sign_verify_remove(self):
        shutil.copyfile(TEST_WARC, TEMP_SIGNED_WARC)

        # save size
        orig_size = os.path.getsize(TEMP_SIGNED_WARC)

        assert self.signer.sign(TEMP_SIGNED_WARC) == True

        # verify signed
        assert self.signer.verify(TEMP_SIGNED_WARC) == True

        # verify against wrong key
        wrong_signer = RSASigner(public_key_file=PUBLIC_WRONG_KEY)
        assert wrong_signer.verify(TEMP_SIGNED_WARC) == False

        # signature added to warc size
        assert os.path.getsize(TEMP_SIGNED_WARC) > orig_size

        # verify and remove sig
        assert self.signer.verify(TEMP_SIGNED_WARC, remove=True) == True

        # should no longer be signed
        assert self.signer.verify(TEMP_SIGNED_WARC) == False

        # should be back to original size
        assert os.path.getsize(TEMP_SIGNED_WARC) == orig_size

        os.remove(TEMP_SIGNED_WARC)

        # original never signed
        assert self.signer.verify(TEST_WARC) == False

    def test_cli_sign(self):
        shutil.copyfile(TEST_WARC, TEMP_SIGNED_WARC)
        assert sign_cli([PRIVATE_KEY, TEMP_SIGNED_WARC]) == 0
        assert verify_cli([PUBLIC_KEY, TEMP_SIGNED_WARC]) == 0

        # wrong key
        assert verify_cli([PUBLIC_WRONG_KEY, TEMP_SIGNED_WARC]) == 1

        # not signed
        assert verify_cli([PUBLIC_KEY, TEST_WARC]) == 1
        os.remove(TEMP_SIGNED_WARC)

    def test_empty_sign(self):
        open(EMPTY_FILE, 'w').close()

        # not signed
        assert self.signer.verify(EMPTY_FILE) == False

        # sign
        assert self.signer.sign(EMPTY_FILE) == True

        # verify signed
        assert self.signer.verify(EMPTY_FILE) == True

        os.remove(EMPTY_FILE)

        # non-existent file
        assert self.signer.sign(EMPTY_FILE) == False
        assert self.signer.verify(EMPTY_FILE) == False

        assert sign_cli([PRIVATE_KEY, EMPTY_FILE]) == 1
        assert verify_cli([PUBLIC_KEY, EMPTY_FILE]) == 1

    def test_stream(self):
        with tempfile.TemporaryFile() as temp:
            temp.write('ABC')
            assert self.signer.sign(temp) == True
            assert self.signer.verify(temp) == True

