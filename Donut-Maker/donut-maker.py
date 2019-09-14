#!/usr/bin/env python3
import sys
import io
import donut
import argparse




banner = """
   ___  _____    
 .'/,-Y"     "~-.  
 l.Y             ^.           
 /\               _\_      Donuts!   
i            ___/"   "\ 
|          /"   "\   o !   
l         ]     o !__./   
 \ _  _    \.___./    "~\  
  X \/ \            ___./  
 ( \ ___.   _..--~~"   ~`-.  
  ` Z,--   /               \    
    \__.  (   /       ______) 
      \   l  /-----~~" /      
       Y   \          / 
       |    "x______.^ 
       |           \    
       j            Y


"""




class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def get_args():
    parser = argparse.ArgumentParser(description='Donut Maker \nBy @CyberVaca - hackplayers.com')
    parser.add_argument('-i', dest='Input_File', type=str, required=True, help='Input File')
    parser.add_argument('-o', dest='Output_File', type=str, required=False, default='payload.bin', help='Output File')
    parser.add_argument('-p', dest='Params', type=str, required=False, help='Optional parameters or command line, separated by comma or semi-colon.' )
    parser.add_argument('-n', dest='Namespace', type=str, required=False, help='Optional class name.class (required for .NET DLL)')
    parser.add_argument('-a', dest='Arch', type=int, required=False, help='Target architecture : 1=x86, 2=amd64, 3=amd64+x86(default)', default="3")
    parser.add_argument('-b', dest='Bypass', type=int, required=False, help='Bypass AMSI/WLDP : 1=skip, 2=abort on fail, 3=continue on fail.(default)')
    parser.add_argument('-m', dest='Method', type=str, required=False, help='Optional method or API name for DLL. (method is required for .NET DLL)')
    return parser.parse_args()
    

def creador_de_donuts(Input_File,Output_File,Params,Arch,Bypass):
    shellcode = donut.create(file=str(Input_File),params=str(Params),arch=(Arch),bypass=(Bypass))
    f = open(Output_File, "wb")
    f.write(shellcode)
    f.close()
    print(Color.YELLOW + '[+] Donut generated successfully: ' + args.Output_File)

def creador_de_donuts_dll(Input_File,Output_File,Params,Arch,Bypass,Namespace,Method):
    shellcode = donut.create(file=str(Input_File),params=str(Params),arch=(Arch),bypass=(Bypass),cls=str(Namespace),method=str(Method))
    f = open(Output_File, "wb")
    f.write(shellcode)
    f.close()
    print(Color.YELLOW + '[+] Donut generated successfully: ' + args.Output_File)

if __name__ == '__main__':
    print(Color.YELLOW + banner)
    args = get_args()

if not ".dll" in args.Input_File:
    if args.Params == None:
        args.Params = None
    if args.Arch == None:
        args.Arch = 3
    if args.Bypass == None:
        args.Bypass = 3
    creador_de_donuts(args.Input_File,args.Output_File,args.Params,args.Arch,args.Bypass)
    exit(0)

if ".dll" in args.Input_File:
    if args.Params == None:
        args.Params = None
    if args.Arch == None:
        args.Arch = 3
    if args.Bypass == None:
        args.Bypass = 3
    if args.Namespace == None: 
        print("You need to enter a Namespace and Class")
        exit(0)
    if args.Method == None:
        print("You need to enter a method :(")
        exit(0)
    creador_de_donuts_dll(args.Input_File,args.Output_File,args.Params,args.Arch,args.Bypass,args.Namespace,args.Method)
