import ctypes
import urllib.parse
from logging import getLogger
from typing import Optional, Any, List
from struct import unpack_from, calcsize

from volatility3.framework.layers import resources

vollog = getLogger(__file__)


WINPMEM_MEMORY_INFO_FIELDS_64 = (
    (["CR3", "NtBuildNumber", "KernBase", "KDBG"] + ["KPCR%02d" % i for i in range(64)])
    + ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead", "NtBuildNumberAddr"]
    + ["Padding%s" % i for i in range(0xFE)]
    + ["NumberOfRuns"]
)
WINPMEM_MEMORY_INFO_FIELDS_32 = (
    (["CR3", "NtBuildNumber", "KernBase", "KDBG"] + ["KPCR%02d" % i for i in range(32)])
    + ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead", "NtBuildNumberAddr"]
    + ["Padding%s" % i for i in range(0xFE)]
    + ["NumberOfRuns"]
)


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method


INFO_IOCTRL = CTL_CODE(0x22, 0x103, 3, 3)
SET_MODE = CTL_CODE(0x22, 0x101, 3, 3)


class WinTypes:
    LPCSTR = ctypes.c_char_p
    DWORD = ctypes.c_uint32
    HANDLE = ctypes.c_void_p
    LPVOID = ctypes.c_void_p
    LPDWORD = ctypes.POINTER(DWORD)
    LARGE_INTEGER = ctypes.c_uint64
    PLARGE_INTEGER = ctypes.POINTER(LARGE_INTEGER)
    BOOL = ctypes.c_bool


if hasattr(ctypes, "windll"):
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_BEGIN = 0

    ctypes.windll.kernel32.CreateFileA.argtypes = [
        WinTypes.LPCSTR,
        WinTypes.DWORD,
        WinTypes.DWORD,
        ctypes.c_void_p,
        WinTypes.DWORD,
        WinTypes.DWORD,
        WinTypes.HANDLE,
    ]
    ctypes.windll.kernel32.CreateFileA.restype = WinTypes.HANDLE

    ctypes.windll.kernel32.CloseHandle.argtypes = [WinTypes.HANDLE]

    ctypes.windll.kernel32.DeviceIoControl.argtypes = [
        WinTypes.HANDLE,
        WinTypes.DWORD,
        WinTypes.LPVOID,
        WinTypes.DWORD,
        WinTypes.LPVOID,
        WinTypes.DWORD,
        WinTypes.LPDWORD,
        ctypes.c_void_p,
    ]
    ctypes.windll.kernel32.DeviceIoControl.restype = WinTypes.BOOL

    ctypes.windll.kernel32.ReadFile.argtypes = [
        WinTypes.HANDLE,
        WinTypes.LPVOID,
        WinTypes.DWORD,
        WinTypes.LPDWORD,
        ctypes.c_void_p,
    ]
    ctypes.windll.kernel32.ReadFile.restype = WinTypes.BOOL

    ctypes.windll.kernel32.SetFilePointerEx.argtypes = [
        WinTypes.HANDLE,
        WinTypes.LARGE_INTEGER,
        WinTypes.PLARGE_INTEGER,
        WinTypes.DWORD,
    ]
    ctypes.windll.kernel32.SetFilePointerEx.restype = WinTypes.BOOL


def readfile(fd, offset, length):
    output_bytes = ctypes.create_string_buffer(length)
    old_offset = WinTypes.LARGE_INTEGER(0)
    _ = ctypes.windll.kernel32.SetFilePointerEx(
        fd, offset, ctypes.byref(old_offset), FILE_BEGIN
    )

    bytes_returned = WinTypes.DWORD(0)
    readfile_result = ctypes.windll.kernel32.ReadFile(
        fd,
        output_bytes,
        len(output_bytes),
        ctypes.byref(bytes_returned),
        ctypes.c_void_p(0),
    )
    if not readfile_result:
        last_error = ctypes.windll.kernel32.GetLastError()

        raise ValueError(f"readfile failed: {last_error}", last_error)

    return output_bytes.raw


def ioctl_wrapper(
    fd, code, input_buffer=b"", input_buffer_size=0, output_length=0x10000
):
    if input_buffer_size != 0:
        input_bytes = ctypes.create_string_buffer(input_buffer_size)
    else:
        input_bytes = ctypes.create_string_buffer(len(input_buffer))

    input_bytes[0 : len(input_buffer)] = input_buffer

    output_bytes = ctypes.create_string_buffer(output_length)
    bytes_returned = WinTypes.DWORD(0)
    result = ctypes.windll.kernel32.DeviceIoControl(
        fd,
        code,
        input_bytes,
        len(input_bytes),
        output_bytes,
        len(output_bytes),
        ctypes.byref(bytes_returned),
        ctypes.c_void_p(0),
    )
    if not result:
        last_error = ctypes.windll.kernel32.GetLastError()

        raise ValueError(f"ioctl {code} failed: {last_error}", last_error, code)

    return output_bytes.raw[0 : bytes_returned.value]


def close_handle(handle):
    ctypes.windll.kernel32.CloseHandle(handle)


class WinPmemFile:
    is_safe = True

    def __init__(self, uri):
        self.uri = uri
        self.current_offset = 0
        self.filepath = f"\\\\.\\{self.uri}"
        self.fd = ctypes.windll.kernel32.CreateFileA(
            self.filepath.encode(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ctypes.c_void_p(0),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ctypes.c_void_p(0),
        )
        if self.fd == WinTypes.HANDLE(-1).value:
            raise ValueError(
                f"Could not open {self.filepath}:{ctypes.windll.kernel32.GetLastError()}"
            )

        self.info = ioctl_wrapper(self.fd, INFO_IOCTRL)
        fmt_string = "Q" * len(WINPMEM_MEMORY_INFO_FIELDS_32)
        memory_parameters = dict(
            zip(WINPMEM_MEMORY_INFO_FIELDS_32, unpack_from(fmt_string, self.info))
        )
        if memory_parameters["KernBase"] > (1 << 32):
            fmt_string = "Q" * len(WINPMEM_MEMORY_INFO_FIELDS_64)
            memory_parameters = dict(
                zip(WINPMEM_MEMORY_INFO_FIELDS_64, unpack_from(fmt_string, self.info))
            )

        offset = calcsize(fmt_string)
        self._segments = []
        for x in range(memory_parameters["NumberOfRuns"]):
            start, length = unpack_from("QQ", self.info, x * 16 + offset)
            self._segments.append((start, start, length))

        self.is_safe = True

    def _get_segment_for_address(self, address):
        for segment_start, read_offset_start, segment_length in self._segments:
            if segment_start <= address < segment_start + segment_length:
                return (segment_start, read_offset_start, segment_length)

        return None

    def _get_next_segment_for_address(self, address):
        for segment_start, read_offset_start, segment_length in self._segments:
            if address < segment_start:
                return (segment_start, read_offset_start, segment_length)

        return None

    def tell(self):
        return self.current_offset

    def seek(self, position, whence=0):
        if whence == 0:
            self.current_offset = position
        elif whence == 1:
            self.current_offset += position
        elif whence == 2:
            last_segment = self._segments[-1]
            self.current_offset = last_segment[0] + last_segment[2]
        else:
            raise RuntimeError(f"Invalid whence: {whence}")

    def read(self, amount):
        to_return = b""
        total_read = 0
        left_to_read = amount
        while total_read < amount:
            segment = self._get_segment_for_address(self.current_offset)
            amount_to_read = 0
            if segment:
                segment_start, read_offset_start, segment_length = segment
                amount_to_read = min(
                    left_to_read, segment_start + segment_length - self.current_offset
                )
                read_bytes = readfile(
                    self.fd,
                    self.current_offset - segment_start + read_offset_start,
                    amount_to_read,
                )
                to_return += read_bytes
            elif not WinPmemFile.is_safe:
                amount_to_read = amount
                to_return += readfile(self.fd, self.current_offset, amount)
            else:
                next_segment = self._get_next_segment_for_address(self.current_offset)
                if not next_segment:
                    raise RuntimeError(
                        f"After end of file read: {hex(self.current_offset)}"
                    )
                next_segment_start, _, _ = next_segment
                amount_to_read = min(
                    left_to_read, next_segment_start - self.current_offset
                )
                to_return += b"\x00" * amount_to_read

            self.current_offset += amount_to_read
            total_read += amount_to_read
            left_to_read -= amount_to_read

        return to_return

    def close(self):
        close_handle(self.fd)

    @staticmethod
    def set_unsafe_mode() -> None:
        WinPmemFile.is_safe = False

    @staticmethod
    def set_safe_mode() -> None:
        WinPmemFile.is_safe = True


class WinpmemHandler(resources.VolatilityHandler):
    @classmethod
    def non_cached_schemes(cls) -> List[str]:
        return ["winpmem"]

    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        if req.type == "winpmem":
            device_uri = "://".join(req.full_url.split("://")[1:])

            return WinPmemFile(device_uri)

        return None
