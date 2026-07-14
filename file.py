import os
import io
from config import DEBUG_LOG_CAP

def reverse_readline(fh: io.TextIOWrapper, buf_size=8192, limit=DEBUG_LOG_CAP):
    """A generator that returns the lines of a file in reverse order"""
    segment = None
    offset = 0
    fh.seek(0, os.SEEK_END)
    file_size = remaining_size = fh.tell()
    while remaining_size > 0 and (limit is None or offset < limit):
        offset = min(file_size, offset + buf_size)
        fh.seek(file_size - offset)
        buffer = fh.read(min(remaining_size, buf_size))
        # remove file's last "\n" if it exists, only for the first buffer
        if remaining_size == file_size and buffer[-1] == ord('\n'):
            buffer = buffer[:-1]
        remaining_size -= buf_size
        lines = buffer.split('\n'.encode())
        # append last chunk's segment to this chunk's last line
        if segment is not None:
            lines[-1] += segment
        segment = lines[0]
        lines = lines[1:]
        # yield lines in this chunk except the segment
        for line in reversed(lines):
            # only decode on a parsed line, to avoid utf-8 decode error
            yield line.decode()
    # Don't yield None if the file was empty
    if segment is not None:
        yield segment.decode()