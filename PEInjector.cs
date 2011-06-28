using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.IO;
using Squared.Task;

namespace Squared.PE {
    public static class PEInjector {
        public static unsafe RemoteMemoryRegion Inject (
            Process process, PortableExecutable executable, IntPtr payloadArgument, 
            Future<Int32> threadResultFuture, Future<UInt32> threadIdFuture
        ) {
            RemoteMemoryRegion region = null;
            using (var handle = Win32.OpenProcessHandle(
                ProcessAccessFlags.VMRead | ProcessAccessFlags.VMWrite |
                ProcessAccessFlags.VMOperation | ProcessAccessFlags.CreateThread | 
                ProcessAccessFlags.QueryInformation, 
                false, process.Id
            )) 
            try {
                region = RemoteMemoryRegion.Allocate(
                    process, handle, executable.OptionalHeader.SizeOfImage
                );
                region.Protect(handle, 0, region.Size, MemoryProtection.ReadWrite);

                var baseAddress = (UInt32)region.Address.ToInt64();

                executable.Rebase(baseAddress);
                executable.ResolveImports();

                foreach (var section in executable.Sections.Values) {
                    // 0-byte remote memory read/write/protect operations will fail with an error.
                    if (section.Size <= 0)
                        continue;

                    fixed (byte* data = section.RawData) {
                        region.Write(
                            handle, section.VirtualAddress, section.Size, data
                        );

                        // Why the fuck isn't this a flags-style enumeration? Sigh, classic windows.
                        MemoryProtection protection = MemoryProtection.ReadOnly;
                        if ((section.Characteristics & PortableExecutable.SectionCharacteristics.MemExecute) == PortableExecutable.SectionCharacteristics.MemExecute)
                            protection = MemoryProtection.ExecuteRead;
                        else if ((section.Characteristics & PortableExecutable.SectionCharacteristics.MemWrite) == PortableExecutable.SectionCharacteristics.MemWrite)
                            protection = MemoryProtection.ReadWrite;

                        region.Protect(
                            handle, section.VirtualAddress, section.Size, protection
                        );
                    }
                }

                UInt32 threadId = 0;
                UInt32 creationFlags = 0x0;
                IntPtr remoteThreadHandle = Win32.CreateRemoteThread(
                    handle.DangerousGetHandle(), IntPtr.Zero, 0,
                    baseAddress + executable.OptionalHeader.AddressOfEntryPoint,
                    payloadArgument,
                    creationFlags, out threadId
                );
                if (remoteThreadHandle == IntPtr.Zero) {
                    var error = Win32.GetLastError();
                    throw new Exception(String.Format("Thread start failed: Error {0:x8}", error));
                }

                threadIdFuture.Complete(threadId);
                var threadHandle = new ThreadWaitHandle(new SafeWaitHandle(remoteThreadHandle, true));
                ThreadPool.RegisterWaitForSingleObject(threadHandle, (s, e) => {
                    Int32 exitCode;
                    Win32.GetExitCodeThread(handle.DangerousGetHandle(), out exitCode);
                    threadResultFuture.Complete(exitCode);
                    threadHandle.Close();
                }, null, -1, true);

                var theResult = region;
                region = null;
                return theResult;
            } finally {
                if (region != null) {
                    bool exited = true;
                    try {
                        exited = process.HasExited;
                    } catch {
                    }

                    if (!exited)
                        region.Dispose();
                }
            }
        }
    }
}
