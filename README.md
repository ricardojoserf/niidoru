# go-processinjection

Different methods for Process Injection using Go

```
go run . -p <PROCESS_NAME> -m <METHOD> 
```
- -p: Process name. Example: notepad.exe

- -m: Process injection method. Options: 1, 2, 3

Example:

```
go run . -p notepad.exe -m 3 
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
main.exe -p <PROCESS_NAME> -m <METHOD>
```
