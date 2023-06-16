#include <ntddk.h>

NTSTATUS MapMemory(ULONG ulAddr, ULONG ulLen, PVOID* ptrBuffer, PMDL* ptrMdl);