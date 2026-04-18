import ctypes
import datetime
from pathlib import Path
from typing import Union

so_path = Path(__file__).parent / "streebog_go" / "streebog_go.so"
streebog_go = ctypes.cdll.LoadLibrary(so_path)

_c_hash256_file = streebog_go.Hash256FileWrapper
_c_hash256_file.argtypes = [ctypes.c_char_p]
_c_hash256_file.restype = ctypes.c_void_p

_c_hash512_file = streebog_go.Hash256FileWrapper
_c_hash512_file.argtypes = [ctypes.c_char_p]
_c_hash512_file.restype = ctypes.c_void_p

_c_hash256_bytes = streebog_go.Hash256BytesWrapper
_c_hash256_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
_c_hash256_bytes.restype = ctypes.c_void_p

_c_hash512_bytes = streebog_go.Hash512BytesWrapper
_c_hash512_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
_c_hash512_bytes.restype = ctypes.c_void_p


def hash256_file(path: Union[str, Path]) -> str:
    path = Path(path).resolve()
    c_res = _c_hash256_file(str(path).encode("utf-8"))
    c_bytes = ctypes.string_at(c_res)
    res = c_bytes.decode("utf-8")
    return res


def hash512_file(path: Union[str, Path]) -> str:
    path = Path(path).resolve()
    c_res = _c_hash512_file(str(path).encode("utf-8"))
    c_bytes = ctypes.string_at(c_res)
    res = c_bytes.decode("utf-8")
    return res


def hash256_bytes(data: bytes) -> str:
    c_res = _c_hash256_bytes(
        (ctypes.c_ubyte * len(data)).from_buffer_copy(data), len(data)
    )
    c_bytes = ctypes.string_at(c_res)
    res = c_bytes.decode("utf-8")
    return res


def hash512_bytes(data: bytes) -> str:
    c_res = _c_hash512_bytes(
        (ctypes.c_ubyte * len(data)).from_buffer_copy(data), len(data)
    )
    c_bytes = ctypes.string_at(c_res)
    res = c_bytes.decode("utf-8")
    return res


def main():
    print(hash256_bytes(b"hello world"))


if __name__ == "__main__":
    main()
