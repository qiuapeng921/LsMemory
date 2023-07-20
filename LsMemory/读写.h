#pragma once

NTSTATUS ReadMemory(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, OUT PVOID Buffer);

NTSTATUS WriteMemory(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, IN PVOID Buffer);

NTSTATUS AllocMemory(IN ULONG ProcessPid, IN SIZE_T Length, OUT PVOID Buffer);

NTSTATUS FreeMemory(IN ULONG ProcessPid, IN PVOID BaseAddress);