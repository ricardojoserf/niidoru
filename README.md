# go-processinjection

Different methods for Process Injection using Go.

```
go run . -m <METHOD> [ -p <PID> ]  [ -n <PROCESS_NAME> ] 
```
- -m (Mandatory): Process injection method. Options: 1, 2, 3

- -p (Optional):  Process ID or PID. Examples: 1234

- -n (Optional):  Process name. Example: notepad.exe

Examples:

```
go run . -m 1 -p notepad.exe 
```

```
go run . -m 2 -p 1234 
```

```
go run . -m 3 -p c:\windows\system32\notepad.exe 
```

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

## Binary

Compile:

```
go build
```

Run:

```` 
main.exe -m <METHOD> [ -n <PROCESS_NAME> ] [ -p <PID> ]
```
