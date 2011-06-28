using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Squared.Task;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Squared.PE {
    public class RPCResponseChannel : NativeWindow, IDisposable {
        protected int WM_RPC_MESSAGE;
        private const int WS_EX_NOACTIVATE = 0x08000000;

        protected Process _Process;
        protected Dictionary<UInt32, Future<byte[]>> _AwaitingResponses = new Dictionary<uint, Future<byte[]>>();
        protected BlockingQueue<byte[]> _Messages = new BlockingQueue<byte[]>();
        protected Random _Random = new Random();

        public UInt32 RemoteThreadId = 0;

        public RPCResponseChannel (Process process, string messageName)
            : base() {
            _Process = process;

            WM_RPC_MESSAGE = Win32.RegisterWindowMessage(messageName);

            var cp = new CreateParams {
                Caption = "Squared.PE.RPCChannel",
                X = 0,
                Y = 0,
                Width = 0,
                Height = 0,
                Style = 0,
                ExStyle = WS_EX_NOACTIVATE,
                Parent = new IntPtr(-3)
            };
            CreateHandle(cp);

            try {
                if (!Win32.ChangeWindowMessageFilterEx(
                    this.Handle, WM_RPC_MESSAGE, MessageFilterFlag.AllowMessage, IntPtr.Zero
                )) {
                    var error = Win32.GetLastError();
                    throw new Exception(String.Format("Error changing window message filter: {0:x8}", error));
                }
            } catch (EntryPointNotFoundException) {
                try {
                    if (!Win32.ChangeWindowMessageFilter(
                        WM_RPC_MESSAGE, MessageFilterFlag.AllowMessage
                    )) {
                        var error = Win32.GetLastError();
                        throw new Exception(String.Format("Error changing window message filter: {0:x8}", error));
                    }
                } catch (EntryPointNotFoundException) {
                }
            }
        }

        protected unsafe byte[] ReadRemoteData (RemoteMemoryRegion region, out UInt32 messageId) {
            using (var handle = region.OpenHandle(ProcessAccessFlags.VMRead)) {
                messageId = BitConverter.ToUInt32(
                    region.ReadBytes(handle, 0, 4), 0
                );

                return region.ReadBytes(handle, 4, region.Size - 4);
            }
        }

        protected override void WndProc (ref Message m) {
            if (m.Msg == WM_RPC_MESSAGE) {
                byte[] messageData = null;
                UInt32 messageID = 0;
                if ((m.WParam != IntPtr.Zero) && (m.LParam != IntPtr.Zero))
                using (var region = RemoteMemoryRegion.Existing(_Process, m.WParam, (uint)m.LParam.ToInt64()))
                    messageData = ReadRemoteData(region, out messageID);

                Future<byte[]> fResult;
                Monitor.Enter(_AwaitingResponses);
                if (_AwaitingResponses.TryGetValue(messageID, out fResult)) {
                    _AwaitingResponses.Remove(messageID);
                    Monitor.Exit(_AwaitingResponses);
                    fResult.SetResult(messageData, null);
                } else {
                    Debug.Assert(messageID == 0);

                    Monitor.Exit(_AwaitingResponses);
                    _Messages.Enqueue(messageData);
                }
            } else {
                base.WndProc(ref m);
            }
        }

        public Future<byte[]> Receive () {
            return _Messages.Dequeue();
        }

        public UInt32 GetMessageID () {
            var buf = new byte[4];
            _Random.NextBytes(buf);
            return BitConverter.ToUInt32(buf, 0);
        }

        public Future<byte[]> WaitForMessage (UInt32 messageID) {
            Future<byte[]> result;

            lock (_AwaitingResponses) {
                if (!_AwaitingResponses.TryGetValue(messageID, out result))
                    _AwaitingResponses[messageID] = result = new Future<byte[]>();
            }

            return result;
        }

        public UInt32 ChannelID {
            get {
                return (UInt32)Handle.ToInt64();
            }
        }

        public void Dispose () {
            foreach (var f in _AwaitingResponses.Values)
                f.Dispose();
            _AwaitingResponses.Clear();

            DestroyHandle();
        }
    }

    public class RPCChannel : RPCResponseChannel {
        public RPCChannel (Process process, string messageName)
            : base(process, messageName) {
        }

        public unsafe void Send (byte[] message) {
            if (_Process == null)
                throw new Exception("No remote process");
            if (RemoteThreadId == 0)
                throw new Exception("No remote thread");

            using (var handle = Win32.OpenProcessHandle(ProcessAccessFlags.VMWrite | ProcessAccessFlags.VMOperation, false, _Process.Id)) {
                RemoteMemoryRegion region;
                UInt32 regionSize = (UInt32)message.Length;

                // leaked on purpose
                region = RemoteMemoryRegion.Allocate(
                    _Process, handle, regionSize
                );

                fixed (byte* pData = message) {
                    try {
                        region.Write(handle, 0, regionSize, pData);
                    } catch {
                        try {
                            region.Dispose();
                        } catch {
                        }
                        throw;
                    }
                }

                if (!Win32.PostThreadMessage(RemoteThreadId, WM_RPC_MESSAGE, region.Address, region.Size)) {
                    var error = Win32.GetLastError();
                    region.Dispose();
                    throw new Exception(String.Format("Error posting thread message: {0:x8}", error));
                }
            }
        }
    }
}
