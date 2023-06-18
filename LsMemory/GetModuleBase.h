#include <ntifs.h>

NTSTATUS GetProcessModuleList(IN HANDLE ProcessId);

NTSTATUS GetModuleBaseAddress(IN HANDLE ProcessId, IN PCWSTR ModuleName, OUT PVOID* BaseAddress);