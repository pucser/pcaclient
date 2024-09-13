import ctypes
import psutil
import re
from colorama import Fore, init


PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]


def dump_and_filter_pca_client(process_name="explorer.exe", search_string="PcaClient"):
    def open_process(pid):
        kernel32 = ctypes.windll.kernel32
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            raise Exception(f"Could not open process with PID {pid}.")
        return process_handle

    def search_text_in_memory(pid, search_string):
        process_handle = open_process(pid)
        kernel32 = ctypes.windll.kernel32
        memory_info = MEMORY_BASIC_INFORMATION()

        address = 0
        search_pattern = re.compile(search_string.encode('utf-8'))

        while kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(memory_info), ctypes.sizeof(memory_info)):
            if memory_info.State == MEM_COMMIT and memory_info.Protect == PAGE_READWRITE:
                buffer = ctypes.create_string_buffer(memory_info.RegionSize)
                bytes_read = ctypes.c_size_t(0)

                if kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, memory_info.RegionSize, ctypes.byref(bytes_read)):
                    data = buffer.raw[:bytes_read.value]

                    decoded_data = data.decode('utf-8', errors='ignore')


                    for line in decoded_data.splitlines():
                        if "PcaClient" in line:
                            print(Fore.YELLOW + f"{line}")

            address += memory_info.RegionSize

        kernel32.CloseHandle(process_handle)

    def get_pid_by_name(process_name):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return proc.info['pid']
        return None

    pid = get_pid_by_name(process_name)

    if pid:

        search_text_in_memory(pid, search_string)
    else:
        print(f"Process {process_name} not found.")

dump_and_filter_pca_client()

