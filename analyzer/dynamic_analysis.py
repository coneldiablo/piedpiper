#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re  # Для обработки строк
import subprocess  # Для вызова strings
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple  # Убедимся, что все нужные типы импортированы

import psutil

try:
    import frida  # type: ignore

    FRIDA_AVAILABLE = True
except ImportError:
    frida = None  # type: ignore
    FRIDA_AVAILABLE = False

# Импорт поведенческого анализа
from .behavioral_analysis import analyze_behavior

try:
    from .evasion_detector import EvasionDetector
    EVASION_AVAILABLE = True
except ImportError:
    EvasionDetector = None  # type: ignore[assignment]
    EVASION_AVAILABLE = False

# Yara
logger = logging.getLogger("dynamic_analysis")
logger.setLevel(logging.DEBUG)

if not EVASION_AVAILABLE:
    logger.warning("EvasionDetector module not found. Sandbox evasion analysis will be disabled.")
try:
    import yara
except ImportError:
    yara = None
    logger.warning("Yara module not found. Memory dump scanning will be disabled.")

if not FRIDA_AVAILABLE:
    logger.warning(
        "Frida module not found. Dynamic analysis will run in degraded mode without instrumentation."
    )

# Обновленный FRIDA_SCRIPT с большим количеством хуков
FRIDA_SCRIPT = r'''
// Helper function to safely read UTF16 string or return null
function readUtf16StringSafe(ptr) {
    try {
        if (ptr.isNull()) return null;
        return ptr.readUtf16String();
    } catch (e) {
        return null; // Or some indicator like '[Read Error]'
    }
}

// Helper function to read buffer as hex string
function readBufferAsHex(ptr, size, maxSize = 64) {
    try {
        if (ptr.isNull() || size <= 0) return null;
        const readSize = Math.min(size, maxSize);
        return Memory.readByteArray(ptr, readSize).hex();
    } catch (e) {
        return '[Read Error]';
    }
}


function sendCall(apiName, argsObj) {
    send({
        "api": apiName,
        "pid": Process.id,
        "args": argsObj,
        "timestamp": Date.now()
    });
}

// Kernel32.dll Hooks
try {
    const kernel32 = Module.load('kernel32.dll');

    // CreateProcessW
    const createProcessW = kernel32.getExportByName("CreateProcessW");
    if (createProcessW) {
        Interceptor.attach(createProcessW, {
            onEnter: function (args) {
                this.info = {
                    "applicationName": readUtf16StringSafe(args[0]),
                    "commandLine": readUtf16StringSafe(args[1])
                    // args[2] -> lpProcessAttributes (usually null)
                    // args[3] -> lpThreadAttributes (usually null)
                    // args[4] -> bInheritHandles
                    // args[5] -> dwCreationFlags
                    // args[6] -> lpEnvironment
                    // args[7] -> lpCurrentDirectory
                    // args[8] -> lpStartupInfo
                    // args[9] -> lpProcessInformation (out)
                };
                this.processInfoPtr = args[9]; // Save for onLeave
            },
            onLeave: function (retval) {
                // Read ProcessInformation struct if available
                if (this.processInfoPtr && !this.processInfoPtr.isNull()) {
                    try {
                        // PROCESS_INFORMATION structure:
                        // HANDLE hProcess;        (Pointer size)
                        // HANDLE hThread;         (Pointer size)
                        // DWORD dwProcessId;      (4 bytes)
                        // DWORD dwThreadId;       (4 bytes)
                        this.info.hProcess = this.processInfoPtr.readPointer();
                        this.info.hThread = this.processInfoPtr.add(Process.pointerSize).readPointer();
                        this.info.dwProcessId = this.processInfoPtr.add(2 * Process.pointerSize).readU32();
                        this.info.dwThreadId = this.processInfoPtr.add(2 * Process.pointerSize + 4).readU32();
                    } catch(e) {
                        this.info.processInfoReadError = e.message;
                    }
                }
                this.info.success = retval.toInt32() !== 0;
                sendCall("CreateProcessW", this.info);
            }
        });
    }

    // WriteFile
    const writeFile = kernel32.getExportByName("WriteFile");
    if (writeFile) {
        Interceptor.attach(writeFile, {
            onEnter: function (args) {
                this.hFile = args[0];
                this.lpBuffer = args[1];
                this.nBytesToWrite = args[2].toUInt32();
                this.info = {
                    "hFile": this.hFile.toString(),
                    "nBytesToWrite": this.nBytesToWrite,
                    "buffer_hex": readBufferAsHex(this.lpBuffer, this.nBytesToWrite, 16) // Read first 16 bytes
                };
            },
            onLeave: function (retval) {
                 // lpNumberOfBytesWritten (optional arg 4)
                this.info.success = retval.toInt32() !== 0;
                sendCall("WriteFile", this.info);
            }
        });
    }

    // CreateRemoteThread
    const createRemoteThread = kernel32.getExportByName("CreateRemoteThread");
    if (createRemoteThread) {
        Interceptor.attach(createRemoteThread, {
            onEnter: function (args) {
                this.info = {
                    "hProcess": args[0].toString(),
                    // lpThreadAttributes (usually null)
                    // dwStackSize
                    "lpStartAddress": args[3].toString(),
                    "lpParameter": args[4].toString(),
                    // dwCreationFlags
                    // lpThreadId (out)
                };
            },
            onLeave: function (retval) {
                this.info.threadHandle = !retval.isNull() ? retval.toString() : null;
                this.info.success = !retval.isNull();
                sendCall("CreateRemoteThread", this.info);
            }
        });
    }

     // WriteProcessMemory
    const writeProcessMemory = kernel32.getExportByName("WriteProcessMemory");
    if (writeProcessMemory) {
        Interceptor.attach(writeProcessMemory, {
            onEnter: function (args) {
                const nSize = args[3].toUInt32();
                this.info = {
                    "hProcess": args[0].toString(),
                    "lpBaseAddress": args[1].toString(),
                    "lpBuffer": args[2].toString(), // Address of the buffer in current process
                    "nSize": nSize,
                    "buffer_hex": readBufferAsHex(args[2], nSize, 16) // Read first 16 bytes from our buffer
                };
            },
            onLeave: function (retval) {
                // lpNumberOfBytesWritten (optional arg 4)
                this.info.success = (retval.toInt32() !== 0);
                sendCall("WriteProcessMemory", this.info);
            }
        });
    }

    // CreateFileW
    const createFileW = kernel32.getExportByName("CreateFileW");
    if (createFileW) {
         Interceptor.attach(createFileW, {
            onEnter: function (args) {
                this.info = {
                    "lpFileName": readUtf16StringSafe(args[0]),
                    "dwDesiredAccess": args[1].toUInt32(),
                    "dwShareMode": args[2].toUInt32(),
                    // lpSecurityAttributes (usually null)
                    "dwCreationDisposition": args[4].toUInt32(),
                    "dwFlagsAndAttributes": args[5].toUInt32()
                    // hTemplateFile (usually null)
                };
            },
            onLeave: function (retval) {
                // Return value is the handle or INVALID_HANDLE_VALUE
                this.info.handle = !retval.isNull() && retval.toInt32() != -1 ? retval.toString() : "INVALID_HANDLE_VALUE";
                this.info.success = this.info.handle !== "INVALID_HANDLE_VALUE";
                sendCall("CreateFileW", this.info);
            }
        });
    }

    // DeleteFileW
    const deleteFileW = kernel32.getExportByName("DeleteFileW");
    if (deleteFileW) {
         Interceptor.attach(deleteFileW, {
            onEnter: function (args) {
                this.info = { "lpFileName": readUtf16StringSafe(args[0]) };
            },
            onLeave: function (retval) {
                this.info.success = retval.toInt32() !== 0;
                sendCall("DeleteFileW", this.info);
            }
        });
    }

    // MoveFileW
    const moveFileW = kernel32.getExportByName("MoveFileW");
    if (moveFileW) {
         Interceptor.attach(moveFileW, {
            onEnter: function (args) {
                this.info = {
                    "lpExistingFileName": readUtf16StringSafe(args[0]),
                    "lpNewFileName": readUtf16StringSafe(args[1])
                 };
            },
            onLeave: function (retval) {
                this.info.success = retval.toInt32() !== 0;
                sendCall("MoveFileW", this.info);
            }
        });
    }

     // ReadFile
    const readFile = kernel32.getExportByName("ReadFile");
    if (readFile) {
         Interceptor.attach(readFile, {
            onEnter: function (args) {
                this.hFile = args[0];
                this.lpBuffer = args[1]; // Buffer to read into
                this.nBytesToRead = args[2].toUInt32();
                this.info = {
                    "hFile": this.hFile.toString(),
                    "nBytesToRead": this.nBytesToRead
                    // lpNumberOfBytesRead (out, arg 3)
                    // lpOverlapped (optional, arg 4)
                };
                 this.lpNumberOfBytesReadPtr = args[3]; // Save pointer for onLeave
            },
            onLeave: function (retval) {
                let bytesRead = 0;
                if (this.lpNumberOfBytesReadPtr && !this.lpNumberOfBytesReadPtr.isNull()) {
                    try { bytesRead = this.lpNumberOfBytesReadPtr.readUInt(); } catch(e){}
                }
                this.info.bytesRead = bytesRead;
                this.info.buffer_hex = readBufferAsHex(this.lpBuffer, bytesRead, 16); // Read what was actually read
                this.info.success = retval.toInt32() !== 0;
                sendCall("ReadFile", this.info);
            }
        });
    }

    // CreateThread
    const createThread = kernel32.getExportByName("CreateThread");
    if (createThread) {
         Interceptor.attach(createThread, {
            onEnter: function (args) {
                 this.info = {
                    // lpThreadAttributes
                    // dwStackSize
                    "lpStartAddress": args[2].toString(),
                    "lpParameter": args[3].toString(),
                    "dwCreationFlags": args[4].toUInt32()
                    // lpThreadId (out)
                };
            },
            onLeave: function (retval) {
                this.info.threadHandle = !retval.isNull() ? retval.toString() : null;
                this.info.success = !retval.isNull();
                sendCall("CreateThread", this.info);
            }
        });
    }

    // ResumeThread
    const resumeThread = kernel32.getExportByName("ResumeThread");
    if (resumeThread) {
         Interceptor.attach(resumeThread, {
            onEnter: function (args) {
                this.info = { "hThread": args[0].toString() };
            },
            onLeave: function (retval) {
                this.info.previousSuspendCount = retval.toInt32(); // -1 indicates error
                this.info.success = retval.toInt32() != -1;
                sendCall("ResumeThread", this.info);
            }
        });
    }

    // TerminateProcess
    const terminateProcess = kernel32.getExportByName("TerminateProcess");
    if (terminateProcess) {
         Interceptor.attach(terminateProcess, {
            onEnter: function (args) {
                this.info = {
                    "hProcess": args[0].toString(),
                    "uExitCode": args[1].toUInt32()
                 };
            },
            onLeave: function (retval) {
                // Returns non-zero on success
                this.info.success = retval.toInt32() !== 0;
                sendCall("TerminateProcess", this.info);
            }
        });
    }

    // OpenProcess
    const openProcess = kernel32.getExportByName("OpenProcess");
    if (openProcess) {
         Interceptor.attach(openProcess, {
            onEnter: function (args) {
                this.info = {
                    "dwDesiredAccess": args[0].toUInt32(),
                    "bInheritHandle": args[1].toInt32() !== 0,
                    "dwProcessId": args[2].toUInt32()
                 };
            },
            onLeave: function (retval) {
                this.info.handle = !retval.isNull() ? retval.toString() : null;
                this.info.success = !retval.isNull();
                sendCall("OpenProcess", this.info);
            }
        });
    }

    // VirtualProtectEx
    const virtualProtectEx = kernel32.getExportByName("VirtualProtectEx");
    if (virtualProtectEx) {
         Interceptor.attach(virtualProtectEx, {
            onEnter: function (args) {
                this.info = {
                    "hProcess": args[0].toString(),
                    "lpAddress": args[1].toString(),
                    "dwSize": args[2].toUInt32(),
                    "flNewProtect": args[3].toUInt32()
                    // lpflOldProtect (out)
                 };
            },
            onLeave: function (retval) {
                this.info.success = retval.toInt32() !== 0;
                sendCall("VirtualProtectEx", this.info);
            }
        });
    }


} catch(e) { console.error("Error loading kernel32.dll hooks: " + e); }


// Ntdll.dll Hooks
try {
    const ntdll = Module.load('ntdll.dll');

    // NtAllocateVirtualMemory
    const ntAllocateVirtualMemory = ntdll.getExportByName("NtAllocateVirtualMemory");
    if (ntAllocateVirtualMemory) {
        Interceptor.attach(ntAllocateVirtualMemory, {
            onEnter: function (args) {
                this.info = {
                    "hProcess": args[0].toString(),
                    "baseAddressPtr": args[1].toString(), // Ptr to Ptr
                    "zeroBits": args[2].toString(),
                    "regionSizePtr": args[3].toString(), // Ptr to size_t
                    "allocType": args[4].toUInt32(),
                    "protect": args[5].toUInt32()
                };
            },
            onLeave: function (retval) {
                 // Read the allocated base address and size back if possible
                 try {
                     if(!this.info.baseAddressPtr.isNull()) {
                        this.info.allocatedBaseAddress = Memory.readPointer(ptr(this.info.baseAddressPtr));
                     }
                     if(!this.info.regionSizePtr.isNull()) {
                         this.info.allocatedRegionSize = Memory.readPointer(ptr(this.info.regionSizePtr)).toUInt32(); // Assuming 32-bit size_t for simplicity here
                     }
                 } catch(e) {}
                 this.info.ntstatus = retval.toString(); // NTSTATUS code
                 sendCall("NtAllocateVirtualMemory", this.info);
            }
        });
    }

} catch(e) { console.error("Error loading ntdll.dll hooks: " + e); }


// Advapi32.dll Hooks (Registry)
try {
    const advapi32 = Module.load('advapi32.dll');

     // RegOpenKeyExW
    const regOpenKeyExW = advapi32.getExportByName("RegOpenKeyExW");
    if (regOpenKeyExW) {
        Interceptor.attach(regOpenKeyExW, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.lpSubKey = readUtf16StringSafe(args[1]);
                this.samDesired = args[3].toUInt32();
                this.phkResultPtr = args[4]; // Pointer to HKEY (out)
                this.info = {
                    "hKey_root": this.hKey.toString(), // Maybe map predefined keys later
                    "lpSubKey": this.lpSubKey,
                    "samDesired": this.samDesired
                };
            },
            onLeave: function (retval) {
                const returnCode = retval.toInt32(); // LSTATUS (0 is ERROR_SUCCESS)
                this.info.returnCode = returnCode;
                this.info.success = returnCode === 0;
                if(this.info.success && this.phkResultPtr && !this.phkResultPtr.isNull()) {
                     try { this.info.hKey_result = this.phkResultPtr.readPointer().toString(); } catch(e){}
                }
                let note = "";
                if (this.lpSubKey && this.lpSubKey.toLowerCase().indexOf("currentversion\run") >= 0) {
                    note = "[Autostart Registry Key]";
                }
                this.info.note = note;
                sendCall("RegOpenKeyExW", this.info);
            }
        });
    }

     // RegCreateKeyExW
    const regCreateKeyExW = advapi32.getExportByName("RegCreateKeyExW");
    if (regCreateKeyExW) {
        Interceptor.attach(regCreateKeyExW, {
             onEnter: function (args) {
                this.hKey = args[0];
                this.lpSubKey = readUtf16StringSafe(args[1]);
                this.lpClass = readUtf16StringSafe(args[3]); // Reserved, Class
                this.dwOptions = args[4].toUInt32();
                this.samDesired = args[5].toUInt32();
                // lpSecurityAttributes (optional)
                this.phkResultPtr = args[7]; // Pointer to HKEY (out)
                this.lpdwDispositionPtr = args[8]; // Pointer to DWORD (out) - REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY
                this.info = {
                    "hKey_root": this.hKey.toString(),
                    "lpSubKey": this.lpSubKey,
                    "dwOptions": this.dwOptions,
                    "samDesired": this.samDesired
                };
            },
            onLeave: function (retval) {
                const returnCode = retval.toInt32();
                this.info.returnCode = returnCode;
                this.info.success = returnCode === 0;
                 if(this.info.success) {
                    if(this.phkResultPtr && !this.phkResultPtr.isNull()) {
                        try { this.info.hKey_result = this.phkResultPtr.readPointer().toString(); } catch(e){}
                    }
                    if(this.lpdwDispositionPtr && !this.lpdwDispositionPtr.isNull()) {
                         try {
                             const disp = this.lpdwDispositionPtr.readUInt();
                             this.info.disposition = (disp == 1) ? "REG_CREATED_NEW_KEY" : (disp == 2) ? "REG_OPENED_EXISTING_KEY" : disp;
                          } catch(e){}
                    }
                 }
                let note = "";
                if (this.lpSubKey && this.lpSubKey.toLowerCase().indexOf("currentversion\run") >= 0) {
                    note = "[Autostart Registry Key Create/Open]";
                }
                this.info.note = note;
                sendCall("RegCreateKeyExW", this.info);
            }
        });
    }

     // RegSetValueExW
    const regSetValueExW = advapi32.getExportByName("RegSetValueExW");
    if (regSetValueExW) {
        Interceptor.attach(regSetValueExW, {
             onEnter: function (args) {
                 const dwType = args[2].toUInt32();
                 const lpData = args[3];
                 const cbData = args[4].toUInt32();
                 let dataStr = "[Binary Data]";
                 // Try to read data based on type (simplified)
                 if (dwType === 1) { // REG_SZ
                     dataStr = readUtf16StringSafe(lpData);
                 } else if (dwType === 2) { // REG_EXPAND_SZ
                     dataStr = readUtf16StringSafe(lpData) + " [Expandable]";
                 } else if (dwType === 4) { // REG_DWORD
                     try { dataStr = "0x" + lpData.readUInt().toString(16); } catch(e) {}
                 } else if (dwType === 3) { // REG_BINARY
                      dataStr = readBufferAsHex(lpData, cbData, 16) + "...";
                 }

                this.info = {
                    "hKey": args[0].toString(),
                    "lpValueName": readUtf16StringSafe(args[1]),
                    "dwType": dwType,
                    "lpData_str": dataStr,
                    "cbData": cbData
                };
            },
            onLeave: function (retval) {
                const returnCode = retval.toInt32();
                this.info.returnCode = returnCode;
                this.info.success = returnCode === 0;
                sendCall("RegSetValueExW", this.info);
            }
        });
    }

     // RegDeleteKeyW
    const regDeleteKeyW = advapi32.getExportByName("RegDeleteKeyW");
    if (regDeleteKeyW) {
        Interceptor.attach(regDeleteKeyW, {
             onEnter: function (args) {
                this.info = {
                    "hKey": args[0].toString(),
                    "lpSubKey": readUtf16StringSafe(args[1])
                };
            },
            onLeave: function (retval) {
                const returnCode = retval.toInt32();
                this.info.returnCode = returnCode;
                this.info.success = returnCode === 0;
                sendCall("RegDeleteKeyW", this.info);
            }
        });
    }

     // RegDeleteValueW
    const regDeleteValueW = advapi32.getExportByName("RegDeleteValueW");
    if (regDeleteValueW) {
        Interceptor.attach(regDeleteValueW, {
             onEnter: function (args) {
                this.info = {
                    "hKey": args[0].toString(),
                    "lpValueName": readUtf16StringSafe(args[1])
                };
            },
            onLeave: function (retval) {
                const returnCode = retval.toInt32();
                this.info.returnCode = returnCode;
                this.info.success = returnCode === 0;
                sendCall("RegDeleteValueW", this.info);
            }
        });
    }

} catch(e) { console.error("Error loading advapi32.dll hooks: " + e); }


// Shell32.dll Hooks
try {
    const shell32 = Module.load('shell32.dll');

    // ShellExecuteW
    const shellExecuteW = shell32.getExportByName("ShellExecuteW");
    if (shellExecuteW) {
        Interceptor.attach(shellExecuteW, {
            onEnter: function (args) {
                this.info = {
                    // hwnd
                    "lpOperation": readUtf16StringSafe(args[1]),
                    "lpFile": readUtf16StringSafe(args[2]),
                    "lpParameters": readUtf16StringSafe(args[3]),
                    "lpDirectory": readUtf16StringSafe(args[4]),
                    "nShowCmd": args[5].toInt32()
                };
            },
            onLeave: function (retval) {
                // Return value > 32 indicates success
                this.info.returnValue = retval.toInt32();
                this.info.success = retval.toInt32() > 32;
                sendCall("ShellExecuteW", this.info);
            }
        });
    }
} catch(e) { console.error("Error loading shell32.dll hooks: " + e); }


// Wininet.dll Hooks
try {
    const wininet = Module.load('wininet.dll');

    // InternetOpenUrlW
    const internetOpenUrlW = wininet.getExportByName("InternetOpenUrlW");
    if (internetOpenUrlW) {
        Interceptor.attach(internetOpenUrlW, {
            onEnter: function (args) {
                this.info = {
                    "hInternet": args[0].toString(),
                    "lpszUrl": readUtf16StringSafe(args[1]),
                    "lpszHeaders": readUtf16StringSafe(args[2]),
                    "dwHeadersLength": args[3].toUInt32(),
                    "dwFlags": args[4].toUInt32()
                    // dwContext
                };
            },
            onLeave: function (retval) {
                this.info.handle = !retval.isNull() ? retval.toString() : null;
                this.info.success = !retval.isNull();
                sendCall("InternetOpenUrlW", this.info);
            }
        });
    }

    // HttpSendRequestW
    const httpSendRequestW = wininet.getExportByName("HttpSendRequestW");
    if (httpSendRequestW) {
        Interceptor.attach(httpSendRequestW, {
            onEnter: function (args) {
                this.info = {
                    "hRequest": args[0].toString(),
                    "lpszHeaders": readUtf16StringSafe(args[1]),
                    "dwHeadersLength": args[2].toUInt32(),
                    "lpOptional": args[3].toString(), // Pointer to optional data
                    "dwOptionalLength": args[4].toUInt32()
                };
                 if(this.info.dwOptionalLength > 0 && !args[3].isNull()) {
                     this.info.optionalDataHex = readBufferAsHex(args[3], this.info.dwOptionalLength, 16);
                 }
            },
            onLeave: function (retval) {
                this.info.success = retval.toInt32() !== 0; // BOOL
                sendCall("HttpSendRequestW", this.info);
            }
        });
    }

     // InternetReadFile
    const internetReadFile = wininet.getExportByName("InternetReadFile");
    if (internetReadFile) {
        Interceptor.attach(internetReadFile, {
            onEnter: function (args) {
                this.hFile = args[0];
                this.lpBuffer = args[1]; // Buffer to read into
                this.nBytesToRead = args[2].toUInt32();
                this.lpdwNumberOfBytesReadPtr = args[3]; // Pointer to DWORD (out)

                this.info = {
                    "hFile": this.hFile.toString(),
                    "dwNumberOfBytesToRead": this.nBytesToRead
                };
            },
            onLeave: function (retval) {
                let bytesRead = 0;
                if (this.lpdwNumberOfBytesReadPtr && !this.lpdwNumberOfBytesReadPtr.isNull()) {
                     try { bytesRead = this.lpdwNumberOfBytesReadPtr.readUInt(); } catch(e) {}
                }
                this.info.dwNumberOfBytesRead = bytesRead;
                this.info.buffer_hex = readBufferAsHex(this.lpBuffer, bytesRead, 16);
                this.info.success = retval.toInt32() !== 0; // BOOL
                sendCall("InternetReadFile", this.info);
            }
        });
    }

     // InternetWriteFile
    const internetWriteFile = wininet.getExportByName("InternetWriteFile");
    if (internetWriteFile) {
        Interceptor.attach(internetWriteFile, {
            onEnter: function (args) {
                const nBytesToWrite = args[2].toUInt32();
                this.info = {
                    "hFile": args[0].toString(),
                    "lpBuffer": args[1].toString(),
                    "dwNumberOfBytesToWrite": nBytesToWrite,
                    "buffer_hex": readBufferAsHex(args[1], nBytesToWrite, 16)
                     // lpdwNumberOfBytesWritten (out)
                };
                 this.lpdwNumberOfBytesWrittenPtr = args[3];
            },
            onLeave: function (retval) {
                 let bytesWritten = 0;
                 if (this.lpdwNumberOfBytesWrittenPtr && !this.lpdwNumberOfBytesWrittenPtr.isNull()) {
                     try { bytesWritten = this.lpdwNumberOfBytesWrittenPtr.readUInt(); } catch(e) {}
                 }
                 this.info.dwNumberOfBytesWritten = bytesWritten;
                 this.info.success = retval.toInt32() !== 0; // BOOL
                 sendCall("InternetWriteFile", this.info);
            }
        });
    }


} catch(e) { console.error("Error loading wininet.dll hooks: " + e); }

// Ws2_32.dll Hooks (Sockets)
try {
    const ws2_32 = Module.load('ws2_32.dll');

    // connect
    const connectFunc = ws2_32.getExportByName("connect");
    if (connectFunc) {
         Interceptor.attach(connectFunc, {
            onEnter: function (args) {
                this.socket = args[0];
                this.sockaddrPtr = args[1];
                this.namelen = args[2].toInt32();
                let ip = "[Unknown Addr Family]";
                let port = 0;
                try {
                    // sockaddr_in structure (IPv4):
                    // sa_family (short, 2 bytes)
                    // sin_port (ushort, 2 bytes, network byte order)
                    // sin_addr (in_addr struct, 4 bytes)
                    // sin_zero (char[8])
                    const family = this.sockaddrPtr.readU16();
                    if (family === 2) { // AF_INET
                        port = ntohs(this.sockaddrPtr.add(2).readU16()); // Network to host short
                        const ipInt = this.sockaddrPtr.add(4).readU32(); // Read IP as 32-bit int
                        // Convert int to dotted decimal
                        ip = ((ipInt >> 0) & 0xff) + '.' +
                             ((ipInt >> 8) & 0xff) + '.' +
                             ((ipInt >> 16) & 0xff) + '.' +
                             ((ipInt >> 24) & 0xff);
                    } else if (family === 23) { // AF_INET6 (more complex parsing)
                         ip = "[IPv6 Addr]";
                         port = ntohs(this.sockaddrPtr.add(2).readU16());
                    }
                } catch(e) { ip = "[Read Error]"; port = 0; }

                this.info = {
                    "socket": this.socket.toString(),
                    "targetIP": ip,
                    "targetPort": port,
                    "addrFamily": family
                };
            },
            onLeave: function (retval) {
                // 0 on success, SOCKET_ERROR (-1) on failure
                this.info.returnValue = retval.toInt32();
                this.info.success = retval.toInt32() === 0;
                sendCall("connect", this.info);
            }
        });
    }

    // send
    const sendFunc = ws2_32.getExportByName("send");
    if(sendFunc) {
         Interceptor.attach(sendFunc, {
            onEnter: function (args) {
                 const len = args[2].toInt32();
                 this.info = {
                     "socket": args[0].toString(),
                     "bufPtr": args[1].toString(),
                     "len": len,
                     "flags": args[3].toInt32(),
                     "buffer_hex": readBufferAsHex(args[1], len, 16)
                 };
            },
            onLeave: function (retval) {
                 // Returns number of bytes sent, or SOCKET_ERROR (-1)
                 this.info.bytesSent = retval.toInt32();
                 this.info.success = retval.toInt32() !== -1;
                 sendCall("send", this.info);
            }
        });
    }

     // recv
    const recvFunc = ws2_32.getExportByName("recv");
    if(recvFunc) {
         Interceptor.attach(recvFunc, {
            onEnter: function (args) {
                 this.socket = args[0];
                 this.bufPtr = args[1]; // Buffer to read into
                 this.len = args[2].toInt32(); // Max len
                 this.flags = args[3].toInt32();
                 this.info = {
                     "socket": this.socket.toString(),
                     "len": this.len,
                     "flags": this.flags
                 };
            },
            onLeave: function (retval) {
                 // Returns number of bytes received, 0 if closed gracefully, or SOCKET_ERROR (-1)
                 const bytesRecv = retval.toInt32();
                 this.info.bytesReceived = bytesRecv;
                 if (bytesRecv > 0) {
                     this.info.buffer_hex = readBufferAsHex(this.bufPtr, bytesRecv, 16);
                 }
                 this.info.success = bytesRecv !== -1;
                 sendCall("recv", this.info);
            }
        });
    }

     // DnsQuery_A (or _W) - Note: This might be deprecated, GetAddrInfoW is preferred
     // Let's try DnsQuery_W first as it's more common with Unicode
     const dnsQueryW = Module.findExportByName("dnsapi.dll", "DnsQuery_W");
     if (dnsQueryW) {
         Interceptor.attach(dnsQueryW, {
             onEnter: function(args) {
                 this.info = {
                     "lpstrName": readUtf16StringSafe(args[0]),
                     "wType": args[1].toUInt16(), // 1 for A, 28 for AAAA
                     "Options": args[2].toUInt32()
                     // Other args are less interesting or context pointers
                 };
             },
             onLeave: function(retval) {
                 // retval is DNS_STATUS (0 = success)
                 // args[4] is ppQueryResultsSet (out pointer to DNS_RECORD*)
                 this.info.status = retval.toInt32();
                 this.info.success = retval.toInt32() === 0;
                 // Reading DNS_RECORD results is complex, skip for now
                 // Could attempt to read first record if status is success
                 sendCall("DnsQuery_W", this.info);
             }
         });
     }


} catch(e) { console.error("Error loading ws2_32.dll hooks: " + e); }

// Helper for network byte order conversion (used in connect hook)
function ntohs(val) {
    return ((val & 0xff) << 8) | ((val >> 8) & 0xff);
}

// Add more hooks here following the pattern...
// try { Module.load(...); getExportByName(...); Interceptor.attach(...); } catch(e) {}

console.log("[+] Frida script loaded and hooks attached.");

'''

FRIDA_HOOK_CATALOG = [
    "CreateProcessW", "WriteFile", "CreateRemoteThread", "WriteProcessMemory", "CreateFileW",
    "DeleteFileW", "MoveFileW", "ReadFile", "CreateThread", "ResumeThread", "TerminateProcess",
    "OpenProcess", "VirtualProtectEx", "NtAllocateVirtualMemory", "RegOpenKeyExW",
    "RegCreateKeyExW", "RegSetValueExW", "RegDeleteKeyW", "RegDeleteValueW", "ShellExecuteW",
    "InternetOpenUrlW", "HttpSendRequestW", "InternetReadFile", "InternetWriteFile", "connect",
    "send", "recv", "DnsQuery_W", "CopyFileW", "CopyFileExW", "ReplaceFileW", "CreateDirectoryW",
    "RemoveDirectoryW", "SetFileAttributesW", "SetCurrentDirectoryW", "GetTempPathW", "CreateMutexW",
    "OpenMutexW", "LoadLibraryW", "LoadLibraryExW", "WinExec", "RegQueryValueExW", "RegEnumValueW",
    "RegCloseKey", "URLDownloadToFileW", "InternetConnectW", "HttpOpenRequestW", "sendto",
    "recvfrom", "bind", "listen", "accept", "WSAConnect", "GetAddrInfoW", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "NtCreateSection", "NtMapViewOfSection",
]

_ADDITIONAL_GENERIC_HOOKS: List[Tuple[str, str, str]] = [
    ("kernel32.dll", "CopyFileW", '{"source": readUtf16StringSafe(args[0]), "destination": readUtf16StringSafe(args[1]), "failIfExists": args[2].toInt32() !== 0}'),
    ("kernel32.dll", "CopyFileExW", '{"source": readUtf16StringSafe(args[0]), "destination": readUtf16StringSafe(args[1]), "flags": args[5].toUInt32()}'),
    ("kernel32.dll", "ReplaceFileW", '{"replacedFile": readUtf16StringSafe(args[0]), "replacementFile": readUtf16StringSafe(args[1]), "backupFile": readUtf16StringSafe(args[2]), "flags": args[3].toUInt32()}'),
    ("kernel32.dll", "CreateDirectoryW", '{"directoryPath": readUtf16StringSafe(args[0])}'),
    ("kernel32.dll", "RemoveDirectoryW", '{"directoryPath": readUtf16StringSafe(args[0])}'),
    ("kernel32.dll", "SetFileAttributesW", '{"path": readUtf16StringSafe(args[0]), "attributes": args[1].toUInt32()}'),
    ("kernel32.dll", "SetCurrentDirectoryW", '{"directoryPath": readUtf16StringSafe(args[0])}'),
    ("kernel32.dll", "GetTempPathW", '{"bufferLength": args[0].toUInt32()}'),
    ("kernel32.dll", "CreateMutexW", '{"name": readUtf16StringSafe(args[2]), "initialOwner": args[1].toInt32() !== 0}'),
    ("kernel32.dll", "OpenMutexW", '{"desiredAccess": args[0].toUInt32(), "inheritHandle": args[1].toInt32() !== 0, "name": readUtf16StringSafe(args[2])}'),
    ("kernel32.dll", "LoadLibraryW", '{"library": readUtf16StringSafe(args[0])}'),
    ("kernel32.dll", "LoadLibraryExW", '{"library": readUtf16StringSafe(args[0]), "flags": args[2].toUInt32()}'),
    ("kernel32.dll", "WinExec", '{"commandLine": readAnsiStringSafe(args[0]), "showWindow": args[1].toUInt32()}'),
    ("advapi32.dll", "RegQueryValueExW", '{"hKey": args[0].toString(), "lpValueName": readUtf16StringSafe(args[1])}'),
    ("advapi32.dll", "RegEnumValueW", '{"hKey": args[0].toString(), "index": args[1].toUInt32()}'),
    ("advapi32.dll", "RegCloseKey", '{"hKey": args[0].toString()}'),
    ("urlmon.dll", "URLDownloadToFileW", '{"url": readUtf16StringSafe(args[1]), "destination": readUtf16StringSafe(args[2]), "reserved": args[3].toString()}'),
    ("wininet.dll", "InternetConnectW", '{"serverName": readUtf16StringSafe(args[1]), "serverPort": args[2].toUInt32(), "service": args[7].toUInt32()}'),
    ("wininet.dll", "HttpOpenRequestW", '{"verb": readUtf16StringSafe(args[1]), "objectName": readUtf16StringSafe(args[2]), "version": readUtf16StringSafe(args[3])}'),
    ("ws2_32.dll", "sendto", '{"socket": args[0].toString(), "length": args[2].toInt32(), "flags": args[3].toInt32()}'),
    ("ws2_32.dll", "recvfrom", '{"socket": args[0].toString(), "length": args[2].toInt32(), "flags": args[3].toInt32()}'),
    ("ws2_32.dll", "bind", '{"socket": args[0].toString()}'),
    ("ws2_32.dll", "listen", '{"socket": args[0].toString(), "backlog": args[1].toInt32()}'),
    ("ws2_32.dll", "accept", '{"socket": args[0].toString()}'),
    ("ws2_32.dll", "WSAConnect", '{"socket": args[0].toString()}'),
    ("ws2_32.dll", "GetAddrInfoW", '{"nodeName": readUtf16StringSafe(args[0]), "serviceName": readUtf16StringSafe(args[1])}'),
    ("ntdll.dll", "NtWriteVirtualMemory", '{"hProcess": args[0].toString(), "baseAddress": args[1].toString(), "bytesToWrite": args[3].toUInt32()}'),
    ("ntdll.dll", "NtProtectVirtualMemory", '{"hProcess": args[0].toString(), "baseAddressPtr": args[1].toString(), "regionSizePtr": args[2].toString(), "newProtect": args[3].toUInt32()}'),
    ("ntdll.dll", "NtCreateSection", '{"sectionHandlePtr": args[0].toString(), "desiredAccess": args[1].toUInt32(), "attributes": args[5].toUInt32(), "protection": args[6].toUInt32()}'),
    ("ntdll.dll", "NtMapViewOfSection", '{"sectionHandle": args[0].toString(), "hProcess": args[1].toString(), "baseAddressPtr": args[2].toString(), "inheritDisposition": args[8].toUInt32(), "allocationType": args[9].toUInt32(), "win32Protect": args[10].toUInt32()}'),
]


def _build_additional_frida_hooks() -> str:
    parts = [
        r'''
function readAnsiStringSafe(ptr) {
    try {
        if (ptr.isNull()) return null;
        return ptr.readAnsiString();
    } catch (e) {
        return null;
    }
}

function attachGenericExport(moduleName, exportName, serializer) {
    try {
        const moduleRef = Module.load(moduleName);
        const exportRef = moduleRef.getExportByName(exportName);
        if (!exportRef) return;
        Interceptor.attach(exportRef, {
            onEnter: function (args) {
                this.info = serializer(args);
            },
            onLeave: function (retval) {
                if (!this.info) this.info = {};
                try {
                    this.info.retval = retval.toString();
                    this.info.success = retval.toInt32() !== 0;
                } catch (e) {
                    this.info.retval = '' + retval;
                }
                sendCall(exportName, this.info);
            }
        });
    } catch (e) {
        console.error("Generic hook failed for " + moduleName + "!" + exportName + ": " + e);
    }
}
'''
    ]
    for module_name, export_name, serializer in _ADDITIONAL_GENERIC_HOOKS:
        parts.append(
            "attachGenericExport('{module}', '{export_name}', function(args) {{ return {serializer}; }});\n".format(
                module=module_name,
                export_name=export_name,
                serializer=serializer,
            )
        )
    return "".join(parts)


FRIDA_SCRIPT += _build_additional_frida_hooks()

# Функция загрузки Yara-правил (адаптирована из static_analysis)
def _load_yara_rules_for_dumps(rules_dir: str) -> Optional[Any]:
    if not yara or not rules_dir or not os.path.isdir(rules_dir):
        logger.info(f"Yara не доступен или директория правил не найдена/не указана: {rules_dir}. Yara-сканирование дампов отключено.")
        return None

    filepaths = {}
    try:
        for filename in os.listdir(rules_dir):
            if filename.lower().endswith(('.yar', '.yara')):
                # Фильтруем правила для памяти (те, что содержат 'memory' в имени)
                # Можно расширить логику фильтрации по необходимости
                filepath = os.path.join(rules_dir, filename)
                namespace = os.path.splitext(filename)[0]
                filepaths[namespace] = filepath

        if not filepaths:
            logger.warning(f"Не найдено Yara-правил в {rules_dir} для сканирования дампов.")
            return None

        logger.debug(f"Компиляция Yara-правил для дампов из: {filepaths}")
        rules = yara.compile(filepaths=filepaths)
        logger.info(f"Успешно скомпилировано {len(filepaths)} файлов Yara-правил для дампов.")
        return rules

    except yara.Error as e:
        logger.error(f"Ошибка компиляции Yara-правил для дампов: {e}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при загрузке Yara-правил для дампов: {e}")
        return None

def _normalise_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        if value > 10**10:
            return float(value) / 1000.0
        return float(value)
    return time.time()


def _extract_event_views(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    file_operations: List[Dict[str, Any]] = []
    registry_operations: List[Dict[str, Any]] = []
    network_events: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []

    file_apis = {
        "CreateFileW", "DeleteFileW", "MoveFileW", "CopyFileW", "CopyFileExW",
        "ReplaceFileW", "CreateDirectoryW", "RemoveDirectoryW", "SetFileAttributesW",
        "SetCurrentDirectoryW", "ReadFile", "WriteFile", "GetTempPathW",
    }
    registry_apis = {
        "RegOpenKeyExW", "RegCreateKeyExW", "RegSetValueExW", "RegDeleteKeyW",
        "RegDeleteValueW", "RegQueryValueExW", "RegEnumValueW", "RegCloseKey",
    }
    network_apis = {
        "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept",
        "WSAConnect", "GetAddrInfoW", "InternetOpenUrlW", "InternetConnectW",
        "HttpOpenRequestW", "HttpSendRequestW", "InternetReadFile", "InternetWriteFile", "DnsQuery_W",
    }

    for call in messages:
        if not isinstance(call, dict):
            continue
        api_name = str(call.get("api", ""))
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        timestamp = _normalise_timestamp(call.get("timestamp"))

        if api_name in file_apis:
            path_value = (
                args.get("lpFileName")
                or args.get("source")
                or args.get("destination")
                or args.get("directoryPath")
                or args.get("path")
                or args.get("replacedFile")
                or args.get("replacementFile")
            )
            file_operations.append(
                {
                    "timestamp": timestamp,
                    "operation": api_name,
                    "path": path_value or "",
                    "pid": call.get("pid"),
                }
            )

        if api_name in registry_apis:
            key_value = args.get("lpSubKey") or args.get("hKey") or args.get("lpValueName") or ""
            registry_operations.append(
                {
                    "timestamp": timestamp,
                    "operation": api_name,
                    "key": key_value,
                    "pid": call.get("pid"),
                }
            )

        if api_name in network_apis:
            network_events.append(
                {
                    "timestamp": timestamp,
                    "api": api_name,
                    "remote_ip": args.get("remoteIp") or args.get("serverName") or args.get("url") or args.get("queryName") or "",
                    "remote_port": args.get("remotePort") or args.get("serverPort") or "",
                    "protocol": "dns" if api_name == "DnsQuery_W" else "tcp",
                    "status": "ok" if args.get("success", True) else "failed",
                }
            )

        description = api_name
        if file_operations and file_operations[-1].get("timestamp") == timestamp and file_operations[-1].get("operation") == api_name:
            description = f"{api_name}: {file_operations[-1].get('path', '')}".strip()
        elif registry_operations and registry_operations[-1].get("timestamp") == timestamp and registry_operations[-1].get("operation") == api_name:
            description = f"{api_name}: {registry_operations[-1].get('key', '')}".strip()
        elif network_events and network_events[-1].get("timestamp") == timestamp and network_events[-1].get("api") == api_name:
            description = f"{api_name}: {network_events[-1].get('remote_ip', '')}".strip()
        timeline.append({"timestamp": timestamp, "event": api_name, "description": description, "pid": call.get("pid")})

    return {
        "file_operations": file_operations,
        "registry_operations": registry_operations,
        "network": network_events,
        "timeline": sorted(timeline, key=lambda item: item.get("timestamp", 0)),
    }


def _capture_process_snapshot() -> Dict[str, Any]:
    processes: Dict[str, Any] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            processes[str(info["pid"])] = {
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline": info.get("cmdline"),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def _capture_filesystem_snapshot(target_path: str) -> Dict[str, Any]:
    directories = []
    target_dir = os.path.dirname(os.path.abspath(target_path))
    if target_dir:
        directories.append(target_dir)
    temp_dir = tempfile.gettempdir()
    if temp_dir and temp_dir not in directories:
        directories.append(temp_dir)

    snapshot: Dict[str, Any] = {"directories": directories, "entries": {}}
    max_entries = 500
    total = 0
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory):
            rel = os.path.relpath(root, directory)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth >= 2:
                dirs[:] = []
            for name in files:
                path = os.path.join(root, name)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                snapshot["entries"][path] = {"size": stat.st_size, "mtime": stat.st_mtime}
                total += 1
                if total >= max_entries:
                    return snapshot
    return snapshot


def _capture_registry_snapshot() -> Dict[str, Any]:
    if os.name != "nt":
        return {"status": "unsupported", "keys": {}}
    watched_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    snapshot: Dict[str, Any] = {"status": "ready", "keys": {}}
    for key in watched_keys:
        try:
            completed = subprocess.run(
                ["reg", "query", key, "/s"],
                capture_output=True,
                text=True,
                timeout=10,
                errors="ignore",
            )
            snapshot["keys"][key] = completed.stdout.splitlines() if completed.returncode == 0 else []
        except Exception as exc:
            snapshot["keys"][key] = [f"error: {exc}"]
    return snapshot


def _capture_system_snapshot(target_path: str) -> Dict[str, Any]:
    return {
        "captured_at": datetime.utcnow().isoformat() + "Z",
        "processes": _capture_process_snapshot(),
        "filesystem": _capture_filesystem_snapshot(target_path),
        "registry": _capture_registry_snapshot(),
    }


def _diff_system_snapshots(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_processes = before.get("processes", {}) or {}
    after_processes = after.get("processes", {}) or {}
    before_files = (before.get("filesystem", {}) or {}).get("entries", {}) or {}
    after_files = (after.get("filesystem", {}) or {}).get("entries", {}) or {}
    before_registry = (before.get("registry", {}) or {}).get("keys", {}) or {}
    after_registry = (after.get("registry", {}) or {}).get("keys", {}) or {}

    created_files = sorted(path for path in after_files.keys() if path not in before_files)
    modified_files = sorted(path for path, metadata in after_files.items() if path in before_files and metadata != before_files[path])
    removed_files = sorted(path for path in before_files.keys() if path not in after_files)
    added_processes = sorted(pid for pid in after_processes.keys() if pid not in before_processes)
    removed_processes = sorted(pid for pid in before_processes.keys() if pid not in after_processes)

    registry_changes = []
    for key in sorted(set(before_registry.keys()) | set(after_registry.keys())):
        before_lines = before_registry.get(key, [])
        after_lines = after_registry.get(key, [])
        if before_lines != after_lines:
            registry_changes.append(
                {
                    "key": key,
                    "added_lines": [line for line in after_lines if line not in before_lines][:20],
                    "removed_lines": [line for line in before_lines if line not in after_lines][:20],
                }
            )

    return {
        "processes": {"added": added_processes, "removed": removed_processes},
        "filesystem": {"created": created_files[:100], "modified": modified_files[:100], "removed": removed_files[:100]},
        "registry": registry_changes[:20],
    }


class DynamicAnalyzer:
    def __init__(self, target_path: str, timeout: int = 60, yara_rules_dir: Optional[str] = './yara_rules'):
        self.target_path = target_path
        self.timeout = timeout
        self.yara_rules_dir = yara_rules_dir # Путь к правилам Yara
        self._messages = []
        self._done = False
        self._session = None
        self._pid = None
        self._child_pids = set()
        self._child_sessions = {}
        self._last_event_time = time.time()
        self._memory_dumps = []
        self._errors = []
        self._enable_child_gating = True
        self._dump_dir = None
        self._compiled_yara_rules = None # Скомпилированные правила для дампов
        self._pre_snapshot: Dict[str, Any] = {}
        self._post_snapshot: Dict[str, Any] = {}
        if EVASION_AVAILABLE and EvasionDetector:
            self._evasion_detector = EvasionDetector()
        else:
            self._evasion_detector = None

    def _on_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            # Извлекаем PID, из которого пришло сообщение
            pid_from_message = payload.get("pid", self._pid) # По умолчанию - основной PID
            
            # Добавляем сообщение в общий список
            self._messages.append(payload) 
            self._last_event_time = time.time()
            api_name = payload.get("api", "")
            args = payload.get("args", {})

            # Логируем вызов с указанием PID источника
            logger.debug(f"[FRIDA:PID={pid_from_message}] API call: {api_name} ARGS={args}")

            # Обновляем логику обработки CreateProcessW (она не меняется, т.к. child PID берется из аргументов)
            if api_name == "CreateProcessW":
                cmd = args.get("commandLine")
                created_pid = self._extract_pid_from_message(payload)
                if created_pid:
                    self._child_pids.add(created_pid)
                    logger.debug(f"[FRIDA:PID={pid_from_message}] Detected creation of child process PID: {created_pid}")
            
            # Обновляем логику вызова дампа памяти
            if api_name == "NtAllocateVirtualMemory" and args.get("success") != False:
                base_addr_str = args.get("allocatedBaseAddress")
                size_str = args.get("allocatedRegionSize")
                protection = args.get("protect")
                hProcess_str = args.get("hProcess") # Хендл процесса, для которого выделяется память
                
                target_pid_for_dump = pid_from_message # По умолчанию дампим память вызвавшего процесса
                
                # Расширенная логика определения целевого процесса для дампа:
                # Если hProcess указывает на другой процесс, пытаемся его идентифицировать
                # Для упрощения используем вызвавший процесс, но можно расширить
                # для поддержки межпроцессного внедрения

                if base_addr_str and size_str:
                    try:
                        address = int(str(base_addr_str), 16) # Убедимся, что base_addr_str - строка
                        size = int(size_str) # Уже должно быть числом
                        if size > 0:
                            logger.info(f"[MEMDUMP] Triggered by PID {pid_from_message} for alloc in PID {target_pid_for_dump} at 0x{address:x}, size {size}, protect {protection}")
                            self._dump_memory_region(target_pid_for_dump, address, size, protection)
                    except Exception as e:
                        logger.error(f"[MEMDUMP] Error parsing address/size for dump from PID {pid_from_message}: {e}")
                        
        elif message["type"] == "error":
            # Ошибки от Frida могут не содержать PID, логгируем как есть
            logger.error(f"[FRIDA Error] {message}") 
            self._errors.append(message)
        else:
            logger.info(f"[FRIDA Other] {message}")

    def _extract_pid_from_message(self, payload):
        """Извлекает PID дочернего процесса из сообщения CreateProcessW"""
        if payload.get("api") == "CreateProcessW":
            args = payload.get("args", {})
            if "dwProcessId" in args:
                return args["dwProcessId"]
        return None

    def _on_child_created(self, child):
        """Обработчик события создания дочернего процесса (для Child Gating)"""
        logger.info(f"[FRIDA] Child process created: {child}")
        child_pid = child.pid
        self._child_pids.add(child_pid)
        
        try:
            # Присоединяемся к дочернему процессу
            session = child.attach()
            self._child_sessions[child_pid] = session
            
            # Загружаем наш скрипт в дочерний процесс
            script = session.create_script(FRIDA_SCRIPT)
            script.on('message', self._on_message)
            script.load()
            
            # Разрешаем процессу продолжить выполнение
            child.resume()
            logger.info(f"[FRIDA] Successfully attached to child process PID={child_pid}")
        except Exception as e:
            logger.error(f"[FRIDA] Failed to attach to child process {child_pid}: {e}")
        
        return frida.CHILD_RESUMED  # Сигнализируем Frida о продолжении выполнения

    def _is_process_alive(self, pid: int) -> bool:
        try:
            p = psutil.Process(pid)
            return p.is_running()
        except psutil.NoSuchProcess:
            return False

    def _kill_process(self, pid: int):
        try:
            p = psutil.Process(pid)
            p.kill()
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")

    def _dump_memory_region(self, pid: int, address: int, size: int, protection: int):
        """Читает и сохраняет указанную область памяти процесса."""
        if not self._dump_dir:
            logger.warning("[MEMDUMP] Dump directory not set, skipping dump.")
            return

        dump_filename = f"dump_{pid}_0x{address:x}_{size}.bin"
        dump_filepath = os.path.join(self._dump_dir, dump_filename)
        
        session = None
        try:
            # Получаем сессию для нужного PID
            if pid == self._pid:
                session = self._session
            elif pid in self._child_sessions:
                session = self._child_sessions[pid]
            
            if not session:
                logger.warning(f"[MEMDUMP] No active session found for PID {pid}, attempting temporary attach.")
                try:
                    session = frida.attach(pid)
                    # НЕЛЬЗЯ вызывать detach() здесь, если это основная сессия!
                except Exception as attach_err:
                    logger.error(f"[MEMDUMP] Failed to attach to PID {pid} for dumping: {attach_err}")
                    return

            logger.debug(f"[MEMDUMP] Reading {size} bytes from PID {pid} at 0x{address:x}")
            memory_data = session.read_bytes(address, size)
            
            with open(dump_filepath, "wb") as f:
                f.write(memory_data)
            
            dump_info = {
                "filepath": dump_filepath,
                "pid": pid,
                "address": f"0x{address:x}",
                "size": size,
                "protection": protection, # Сохраняем права доступа
                "timestamp": time.time()
            }
            self._memory_dumps.append(dump_info)
            logger.info(f"[MEMDUMP] Successfully dumped memory to {dump_filepath}")

        except frida.TransportError as te:
             logger.error(f"[MEMDUMP] Frida transport error for PID {pid} at 0x{address:x}: {te}. Process might have exited.")
        except Exception as e:
            logger.error(f"[MEMDUMP] Failed to dump memory for PID {pid} at 0x{address:x}: {e}")
        finally:
            # Отсоединяемся только если это была временная сессия
            if session and pid != self._pid and pid not in self._child_sessions:
                 try:
                      session.detach()
                 except Exception as detach_err:
                      logger.warning(f"[MEMDUMP] Error detaching temporary session for PID {pid}: {detach_err}")

    def _get_process_context(self, pid: int):
        try:
            p = psutil.Process(pid)
            ctx = {
                "pid": pid,
                "cmdline": p.cmdline(),
                "ppid": p.ppid(),
                "exe": p.exe(),
                "cwd": p.cwd(),
                "create_time": p.create_time(),
                "connections": [c._asdict() for c in p.connections()],
                "dlls": [m.path for m in p.memory_maps() if m.path.endswith('.dll')]
            }
            return ctx
        except Exception as e:
            logger.error(f"Failed to get context for {pid}: {e}")
            return {}

    def _scan_memory_dump(self, dump_filepath: str) -> dict:
        """Сканирует один файл дампа памяти на строки и Yara-совпадения."""
        results = {
            "strings": [],
            "yara_matches": []
        }
        if not os.path.isfile(dump_filepath):
            return results

        # 1. Извлечение строк (используем strings или Python re)
        try:
            # Попробуем вызвать утилиту strings, если она есть
            # Опции: -a сканировать весь файл, -t x показать смещение в hex
            # Можно добавить -el для Unicode (little endian)
            process = subprocess.run(['strings', '-a', '-n', '6', dump_filepath], 
                                     capture_output=True, text=True, timeout=30, errors='ignore')
            if process.returncode == 0:
                # Убираем пустые строки и дубликаты
                lines = {line.strip() for line in process.stdout.splitlines() if line.strip()}
                results["strings"] = sorted(list(lines))
            else:
                logger.warning(f"Утилита 'strings' не найдена или завершилась с ошибкой для {dump_filepath}. Строки не извлечены.")
                # Fallback: можно попробовать regex в Python, но это медленнее и менее эффективно
        except FileNotFoundError:
             logger.warning(f"Утилита 'strings' не найдена в PATH. Строки не извлечены из {dump_filepath}.")
        except subprocess.TimeoutExpired:
            logger.warning(f"Извлечение строк из {dump_filepath} превысило таймаут.")
        except Exception as e:
            logger.error(f"Ошибка при извлечении строк из {dump_filepath}: {e}")

        # 2. Yara-сканирование
        if self._compiled_yara_rules:
            try:
                matches = self._compiled_yara_rules.match(dump_filepath)
                for match in matches:
                    results["yara_matches"].append({
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta,
                        # Можно добавить строки и смещения из match.strings
                        'strings_in_match': [(s_id, hex(offset), data[:100]) for s_id, offset, data in match.strings]
                    })
            except yara.Error as e:
                logger.error(f"Ошибка Yara-сканирования дампа {dump_filepath}: {e}")
            except Exception as e:
                 logger.error(f"Неожиданная ошибка Yara-сканирования дампа {dump_filepath}: {e}")
        else:
            logger.debug("Yara-правила не загружены, сканирование дампа пропускается.")

        return results

    def start_analysis(self) -> dict:
        import sys
        # Если frida недоступна, возвращаем пустой результат с ошибкой
        if frida is None:
            err_msg = "Frida не установлена. Установите пакет frida (и при желании frida-tools), либо используйте другие режимы анализа."
            self._errors = [{"type": "missing_dependency", "message": err_msg}]
            return {
                "process_path": self.target_path,
                "api_calls": [],
                "pid": None,
                "context": {},
                "child_processes": {},
                "memory_dumps": [],
                "dump_directory": None,
                "memory_dump_analysis": {},
                "behavioral_patterns": [],
                "file_operations": [],
                "registry_operations": [],
                "network": [],
                "timeline": [],
                "hook_catalog": FRIDA_HOOK_CATALOG,
                "hook_catalog_size": len(FRIDA_HOOK_CATALOG),
                "runtime_capabilities": {
                    "frida_available": False,
                    "platform": sys.platform,
                    "windows_snapshot_support": os.name == "nt",
                    "reason": "frida_not_installed",
                },
                "system_snapshots": {"pre": {}, "post": {}, "diff": {}},
                "errors": self._errors,
            }
        self._messages = []
        self._memory_dumps = []
        self._errors = []
        self._child_pids = set()
        self._child_sessions = {}
        self._compiled_yara_rules = None
        memory_dump_analysis_results = {}
        behavioral_patterns = [] # Список для результатов поведенческого анализа
        sandbox_evasion = {"score": 0, "vm_checks": [], "timing_attacks": [], "summary": "Dynamic analysis skipped"}
        self._pre_snapshot = _capture_system_snapshot(self.target_path) if os.name == "nt" else {}
        self._post_snapshot = {}

        # Загружаем Yara-правила для дампов
        if yara:
             self._compiled_yara_rules = _load_yara_rules_for_dumps(self.yara_rules_dir)

        # Создаем директорию для дампов
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._dump_dir = os.path.join(os.getcwd(), f"memory_dumps_{ts}")
        try:
            os.makedirs(self._dump_dir, exist_ok=True)
            logger.info(f"Memory dumps will be saved to: {self._dump_dir}")
        except Exception as e:
            logger.error(f"Failed to create dump directory {self._dump_dir}: {e}")
            self._dump_dir = None # Не сможем сохранять дампы
        
        device = None # Инициализируем device
        try:
            if sys.platform.startswith("win"):
                device = frida.get_local_device()
                # Настройка Child Gating только если поддерживается
                if self._enable_child_gating and hasattr(device, 'enable_child_gating'):
                    try:
                        device.on('child-added', self._on_child_created)
                        device.enable_child_gating()
                        logger.info("[FRIDA] Child Gating enabled")
                    except Exception as cg_ex:
                        logger.warning(f"[FRIDA] Child Gating not supported: {cg_ex}")
                self._pid = frida.spawn(self.target_path)
            else:
                # Child gating: на Linux/macOS используем простой spawn
                # В будущем можно добавить аргументы и опции через конфиг
                self._pid = frida.spawn([self.target_path])
            
            logger.info(f"Spawned PID={self._pid} for {self.target_path}")
            self._session = frida.attach(self._pid)
            logger.info("Attached frida session")
            script = self._session.create_script(FRIDA_SCRIPT)
            script.on('message', self._on_message)
            script.load()
            logger.info("Loaded hooking script")
            frida.resume(self._pid)
            logger.info("Resumed process execution")
            
            t0 = time.time()
            while time.time() - t0 < self.timeout:
                if not self._is_process_alive(self._pid):
                    logger.info("Target process exited.")
                    break
                # Проверяем активность дочерних процессов тоже?
                all_pids = list(self._child_pids) + [self._pid]
                if not any(self._is_process_alive(p) for p in all_pids if p is not None):
                     logger.info("Target process and all known children exited.")
                     break
                     
                if time.time() - self._last_event_time > 10:
                    logger.info("No interesting events for 10 seconds, finishing early.")
                    break
                time.sleep(0.5)
                
        except Exception as analysis_ex:
            logger.error(f"[ANALYSIS ERROR] An error occurred during analysis setup or execution: {analysis_ex}")
            self._errors.append({"type": "analysis_error", "message": str(analysis_ex)})
        finally:
            # === Очистка ресурсов ===
            logger.info("Starting analysis cleanup...")
            # Отсоединяемся от всех дочерних процессов и завершаем их
            active_children = list(self._child_pids) # Копируем перед итерацией
            for cpid in active_children:
                if cpid in self._child_sessions:
                    try:
                        logger.debug(f"Detaching from child PID {cpid}...")
                        self._child_sessions[cpid].detach()
                    except Exception as e:
                        logger.error(f"Error detaching from child process {cpid}: {e}")
                    del self._child_sessions[cpid]
                        
                if self._is_process_alive(cpid):
                    logger.debug(f"Killing child PID {cpid}...")
                    self._kill_process(cpid)
            
             # Завершаем основной процесс, если он еще жив
            if self._pid and self._is_process_alive(self._pid):
                logger.info("Killing main target process...")
                self._kill_process(self._pid)
                
            # Отсоединяемся от основного процесса
            if self._session:
                try:
                     logger.debug("Detaching from main session...")
                     self._session.detach()
                except Exception as e:
                     logger.error(f"Error detaching main session: {e}")
                self._session = None
            
            # Отключаем Child Gating только если поддерживается
            if self._enable_child_gating and device and hasattr(device, 'disable_child_gating'):
                try:
                    logger.debug("Disabling Child Gating...")
                    device.off('child-added', self._on_child_created) # Убираем обработчик
                    device.disable_child_gating()
                    logger.info("[FRIDA] Child Gating disabled")
                except Exception as e:
                    logger.error(f"Error disabling Child Gating: {e}")
            
            logger.info("Cleanup finished.")

            # === Сканирование дампов памяти ===
            if self._dump_dir and os.path.isdir(self._dump_dir):
                 logger.info(f"Scanning memory dumps in {self._dump_dir}...")
                 for dump_info in self._memory_dumps:
                     dump_filepath = dump_info.get("filepath")
                     if dump_filepath and os.path.isfile(dump_filepath):
                         logger.debug(f"Scanning dump file: {dump_filepath}")
                         scan_result = self._scan_memory_dump(dump_filepath)
                         memory_dump_analysis_results[dump_filepath] = scan_result
                     else:
                         logger.warning(f"Dump file path not found or invalid in dump_info: {dump_info}")
                 logger.info("Memory dump scanning finished.")
            else:
                 logger.info("No memory dumps were created or dump directory is invalid, skipping scanning.")
                 
            # === Поведенческий анализ ===
            logger.info("Starting behavioral pattern analysis...")
            try:
                # Вызываем функцию анализа поведения, передавая собранные вызовы API
                behavioral_patterns = analyze_behavior(self._messages)
                logger.info(f"Behavioral analysis finished. Found {len(behavioral_patterns)} patterns.")
                if self._evasion_detector:
                    sandbox_evasion = self._evasion_detector.analyse(self._messages)
                else:
                    sandbox_evasion = {
                        "score": 0,
                        "vm_checks": [],
                        "timing_attacks": [],
                        "summary": "Sandbox evasion analysis skipped: detector module unavailable",
                    }
            except Exception as beh_ex:
                logger.error(f"Error during behavioral analysis: {beh_ex}")
                self._errors.append({"type": "behavioral_analysis_error", "message": str(beh_ex)})
                sandbox_evasion = {
                    "score": 0,
                    "vm_checks": [],
                    "timing_attacks": [],
                    "summary": f"Sandbox evasion analysis failed: {beh_ex}",
                }

        # Сбор финального контекста
        self._post_snapshot = _capture_system_snapshot(self.target_path) if os.name == "nt" else {}
        event_views = _extract_event_views(self._messages)
        system_snapshots = {
            "pre": self._pre_snapshot,
            "post": self._post_snapshot,
            "diff": _diff_system_snapshots(self._pre_snapshot, self._post_snapshot) if self._pre_snapshot and self._post_snapshot else {},
        }
        context = self._get_process_context(self._pid) if self._pid else {}
        child_contexts = {cpid: self._get_process_context(cpid) for cpid in self._child_pids if cpid != self._pid and self._is_process_alive(cpid)}
        
        return {
            "process_path": self.target_path,
            "api_calls": self._messages,
            "pid": self._pid,
            "context": context,
            "child_processes": child_contexts,
            "memory_dumps": self._memory_dumps,
            "dump_directory": self._dump_dir,
            "memory_dump_analysis": memory_dump_analysis_results,
            "behavioral_patterns": behavioral_patterns,
            "file_operations": event_views["file_operations"],
            "registry_operations": event_views["registry_operations"],
            "network": event_views["network"],
            "timeline": event_views["timeline"],
            "hook_catalog": FRIDA_HOOK_CATALOG,
            "hook_catalog_size": len(FRIDA_HOOK_CATALOG),
            "runtime_capabilities": {
                "frida_available": True,
                "platform": sys.platform,
                "windows_snapshot_support": os.name == "nt",
                "hook_catalog_size": len(FRIDA_HOOK_CATALOG),
            },
            "system_snapshots": system_snapshots,
            "sandbox_evasion": sandbox_evasion,
            "errors": self._errors
        }


def dynamic_analysis(filepath: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Execute dynamic analysis with graceful degradation when Frida is unavailable.
    """
    if not FRIDA_AVAILABLE:
        return _dynamic_analysis_stub(filepath, reason="frida_not_available")

    try:
        analyzer = DynamicAnalyzer(filepath, timeout=timeout)
        result = analyzer.start_analysis()
        if not isinstance(result, dict):
            logger.warning("Dynamic analysis returned unexpected payload type: %s", type(result))
            return _dynamic_analysis_stub(filepath, reason="invalid_result")
        return result
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.error("Dynamic analysis failed for %s: %s", filepath, exc)
        fallback = _dynamic_analysis_stub(filepath, reason="analysis_failure")
        fallback["error"] = str(exc)
        return fallback


def _dynamic_analysis_stub(filepath: str, *, reason: str) -> Dict[str, Any]:
    """Return a placeholder dynamic analysis payload when execution is skipped."""
    return {
        "status": "skipped",
        "reason": reason,
        "file": os.path.abspath(filepath),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "api_calls": [],
        "network": [],
        "file_operations": [],
        "registry_operations": [],
        "timeline": [],
        "behavioral_patterns": [],
        "memory_dumps": [],
        "hook_catalog": FRIDA_HOOK_CATALOG,
        "hook_catalog_size": len(FRIDA_HOOK_CATALOG),
        "runtime_capabilities": {
            "frida_available": False,
            "platform": os.name,
            "windows_snapshot_support": os.name == "nt",
            "reason": reason,
            "hook_catalog_size": len(FRIDA_HOOK_CATALOG),
        },
        "system_snapshots": {"pre": {}, "post": {}, "diff": {}},
        "errors": [
            {
                "message": "Dynamic analysis skipped",
                "reason": reason,
            }
        ],
        "notes": "Install frida-server and the frida Python package to enable dynamic analysis.",
        "sandbox_evasion": {"score": 0, "vm_checks": [], "timing_attacks": [], "summary": "Dynamic analysis unavailable"},
    }


def dynamic_analysis_to_json(filepath: str, outpath: str, timeout: int = 60) -> dict:
    import json
    res = dynamic_analysis(filepath, timeout=timeout)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    return res


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dynamic_analysis.py <path_to_exe> [timeout]")
        sys.exit(0)

    exe_path = sys.argv[1]
    tmo = 60
    if len(sys.argv) >= 3:
        tmo = int(sys.argv[2])

    analysis_result = dynamic_analysis(exe_path, timeout=tmo)
    print("[*] Dynamic analysis result:")
    print(analysis_result)
