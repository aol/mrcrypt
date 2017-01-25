import os
import stat

import pytest

import mrcrypt.io

FILE_CONTENTS = 'this is a string'


@pytest.mark.parametrize('permissions_octal', (
    0100600,
    0100660,
    0100666
))
def test_write_str__file_permissions(tmpdir, permissions_octal):
    filename = tmpdir.join('test.txt').strpath
    mrcrypt.io.write_str(filename, '', FILE_CONTENTS, permissions_octal)

    assert os.stat(filename)[stat.ST_MODE] == permissions_octal
    with open(filename) as f:
        assert f.read() == FILE_CONTENTS
