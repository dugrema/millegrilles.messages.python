import logging
import pathlib
import tarfile

from io import BytesIO
from typing import Optional

# Note : Inspired from source https://gist.github.com/abbbi/b4b07efd133cdc5f86c0da01a030e76a
#        Added multiple file support, directory recursion.

BLOCK_SIZE = 64 * 1024
LOGGER = logging.getLogger(__name__)

class FileStream(object):
    def __init__(self):
        self.buffer = BytesIO()
        self.offset = 0

    def write(self, s):
        self.buffer.write(s)
        self.offset += len(s)

    def tell(self):
        return self.offset

    def close(self):
        self.buffer.close()

    def pop(self):
        s = self.buffer.getvalue()
        self.buffer.close()

        self.buffer = BytesIO()

        return s


def stream_build_tar(in_path: pathlib.Path, streaming_fp):
    tar = tarfile.TarFile.open(None, 'w|gz', streaming_fp)

    if in_path.is_dir():
        for i in stream_build_tar_dir(tar, in_path):
            yield
    elif in_path.is_file():
        for i in stream_build_tar_file(tar, in_path):
            yield
    else:
        LOGGER.warning("Path %s cannot be put in tar file" % in_path)

    tar.close()
    yield


def stream_build_tar_dir(tar: tarfile.TarFile, in_path: pathlib.Path, parent: Optional[str] = None):
    if in_path.is_dir() is False:
        raise Exception('stream_build_tar_file Must be a file')

    if parent:
        parent_path = '%s%s/' % (parent, in_path.name)
    else:
        parent_path = '/'

    for file in in_path.iterdir():
        if file.is_dir():
            for i in stream_build_tar_dir(tar, file, parent_path):
                yield
        elif file.is_file():
            for i in stream_build_tar_file(tar, file, parent_path):
                yield
        else:
            LOGGER.warning("Path %s cannot be put in tar file" % file)
    yield


def stream_build_tar_file(tar: tarfile.TarFile, in_path: pathlib.Path, parent: Optional[str] = None):
    if in_path.is_file() is False:
        raise Exception('stream_build_tar_file Must be a file')

    # Note that we don't pass a fileobj, so we don't write any data
    # through addfile. We'll do this ourselves.
    if parent and parent != '/':
        filename = '%s%s' % (parent, in_path.name)
    else:
        filename = in_path.name

    tar_info = tarfile.TarInfo(filename)
    stat = in_path.stat()
    tar_info.mtime = stat.st_mtime
    tar_info.size = stat.st_size
    tar.addfile(tar_info)

    yield

    with open(in_path, 'rb') as in_fp:
        while True:
            s = in_fp.read(BLOCK_SIZE)

            if len(s) > 0:
                tar.fileobj.write(s)

                yield

            if len(s) < BLOCK_SIZE:
                blocks, remainder = divmod(tar_info.size, tarfile.BLOCKSIZE)

                if remainder > 0:
                    tar.fileobj.write(tarfile.NUL *
                                      (tarfile.BLOCKSIZE - remainder))

                    yield

                    blocks += 1

                tar.offset += blocks * tarfile.BLOCKSIZE
                break

    yield


def stream_path_to_tar(in_path: pathlib.Path, out_fp) -> int:
    total_size = 0
    streaming_fp = FileStream()
    for i in stream_build_tar(in_path, streaming_fp):
        s = streaming_fp.pop()
        out_fp.write(s)
        total_size += len(s)

    return total_size
