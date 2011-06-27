using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Squared.PE {
    public class RemoteMemoryRegion : IDisposable {
        public Process Process;
        public IntPtr Address;
        public UInt32 Size;

        private RemoteMemoryRegion () {
        }

        public static RemoteMemoryRegion Allocate (Process process, UInt32 size) {
            using (var handle = Win32.OpenProcessHandle(
                ProcessAccessFlags.VMOperation | ProcessAccessFlags.VMRead | ProcessAccessFlags.VMWrite,
                false, process.Id
            )) {
                return Allocate(process, handle, size);
            }
        }

        public static RemoteMemoryRegion Allocate (Process process, SafeProcessHandle handle, UInt32 size) {
            var result = new RemoteMemoryRegion {
                Process = process,
                Size = size
            };
            result.Address = Win32.VirtualAllocEx(
                handle.DangerousGetHandle(), IntPtr.Zero,
                size, AllocationType.Commit | AllocationType.Reserve,
                MemoryProtection.ReadWrite
            );
            if (result.Address == IntPtr.Zero) {
                var error = Win32.GetLastError();
                throw new Exception(String.Format("Allocation failed: Error {0:x8}", error));
            }
            return result;
        }

        public static RemoteMemoryRegion Existing (Process process, IntPtr address, UInt32 size) {
            return new RemoteMemoryRegion {
                Process = process,
                Address = address,
                Size = size
            };
        }

        public unsafe int Write (SafeProcessHandle handle, uint offset, uint size, byte* data) {
            if (Address == IntPtr.Zero)
                throw new ObjectDisposedException("RemoteMemoryRegion");
            if ((offset + size) > Size)
                throw new ArgumentException("Size too large for region");

            int bytesWritten = 0;
            int result = Win32.WriteProcessMemory(
                handle.DangerousGetHandle(),
                (uint)(Address.ToInt64() + offset),
                new IntPtr(data), size, out bytesWritten
            );

            if (result == 0 || bytesWritten != size) {
                var error = Win32.GetLastError();
                throw new Exception(String.Format("Write failed: Error {0:x8}", error));
            }

            return bytesWritten;
        }

        private unsafe int Read (SafeProcessHandle handle, uint offset, uint size, byte* pBuffer) {
            if (Address == IntPtr.Zero)
                throw new ObjectDisposedException("RemoteMemoryRegion");
            if ((offset + size) > Size)
                throw new ArgumentException("Size too large for region");

            int bytesRead = 0, result;
            result = Win32.ReadProcessMemory(
                handle.DangerousGetHandle(),
                (uint)(Address.ToInt64() + offset),
                new IntPtr(pBuffer), size, out bytesRead
            );

            if (result == 0 || bytesRead != size) {
                var error = Win32.GetLastError();
                throw new Exception(String.Format("Read failed: Error {0:x8}", error));
            }

            return bytesRead;
        }

        public unsafe int Read (SafeProcessHandle handle, uint offset, uint size, byte[] buffer) {
            if ((buffer == null) || (size != buffer.Length))
                throw new ArgumentException("Invalid buffer to read into");

            fixed (byte* pBuffer = buffer)
                return Read(handle, offset, size, pBuffer);
        }

        public byte[] ReadBytes (SafeProcessHandle handle, uint offset, uint size) {
            if (size == 0)
                return null;

            byte[] buffer = new byte[size];
            Read(handle, offset, (uint)size, buffer);
            return buffer;
        }

        public void Protect (SafeProcessHandle handle, uint offset, uint size, MemoryProtection newProtect) {
            if (Address == IntPtr.Zero)
                throw new ObjectDisposedException("RemoteMemoryRegion");
            if ((offset + size) > (Size))
                throw new ArgumentException("Size too large for region");

            MemoryProtection oldProtect;
            int result = Win32.VirtualProtectEx(
                handle.DangerousGetHandle(),
                (uint)(Address.ToInt64() + offset),
                size, newProtect, out oldProtect
            );

            if (result == 0) {
                var error = Win32.GetLastError();
                throw new Exception(String.Format("Protect failed: Error {0:x8}", error));
            }
        }

        public SafeProcessHandle OpenHandle (ProcessAccessFlags flags) {
            return Win32.OpenProcessHandle(flags, false, Process.Id);
        }

        public void Dispose () {
            if (Address == IntPtr.Zero)
                return;

            try {
                if (Process.HasExited)
                    return;
            } catch {
                return;
            }

            using (var handle = OpenHandle(ProcessAccessFlags.VMOperation | ProcessAccessFlags.VMRead | ProcessAccessFlags.VMWrite)) {
                int result = Win32.VirtualFreeEx(
                    handle.DangerousGetHandle(),
                    Address, 0, FreeType.Release
                );

                if (result == 0) {
                    var error = Win32.GetLastError();

                    throw new Exception(String.Format(
                        "Failed to free region: Error {0:x8}", error
                    ));
                } else {
                    Address = IntPtr.Zero;
                    Size = 0;
                }
            }
        }
    }
}
