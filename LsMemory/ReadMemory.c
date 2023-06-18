#include "ReadMemory.h"

NTSTATUS ReadDirect(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
{
	// Check for invalid parameters
	if (pBaseAddress >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize < (ULONG64)pBaseAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (pBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	// Lookup the process by ID
	PEPROCESS pEprocess = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(hProcessID, &pEprocess);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	// Check if the process has exited
	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	// Allocate memory and copy data from the target process
	PVOID pMemory = ExAllocatePoolWithTag(NonPagedPoolNx, szBufferSize, 'tag');
	if (!pMemory)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(pMemory, szBufferSize);

	KAPC_STATE kApc = { 0 };
	KeStackAttachProcess(pEprocess, &kApc);

	if (MmIsAddressValid(pBaseAddress) && MmIsAddressValid((PVOID)((ULONG64)pBaseAddress + szBufferSize)))
	{
		memcpy(pMemory, pBaseAddress, szBufferSize);
		ntStatus = STATUS_SUCCESS;
	}
	else
	{
		ntStatus = STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);

	// Copy the data to the user buffer
	if (NT_SUCCESS(ntStatus))
	{
		memcpy(pBuffer, pMemory, szBufferSize);
	}

	ExFreePoolWithTag(pMemory, 'tag');
	return ntStatus;
}

NTSTATUS ReadVirtualMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
{
	if ((ULONG64)pBaseAddress >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize < (ULONG64)pBaseAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	if (pBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess;
	KAPC_STATE kApc = { 0 };
	NTSTATUS ntStatus = PsLookupProcessByProcessId(hProcessID, &pEprocess);
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}
	SIZE_T szSize = NULL;
	ntStatus = MmCopyVirtualMemory(pEprocess, pBaseAddress, IoGetCurrentProcess(), pBuffer, szBufferSize, UserMode, &szSize);

	ObDereferenceObject(pEprocess);

	return ntStatus;
}

NTSTATUS Cr3ReadMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
{
	// Check for invalid parameters
	if ((ULONG64)pBaseAddress >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize < (ULONG64)pBaseAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	if (pBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	// Lookup the process by ID
	PEPROCESS pEprocess = NULL;
	NTSTATUS ntStatus = PsLookupProcessByProcessId(hProcessID, &pEprocess);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	// Check if the process has exited
	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	// Allocate memory and copy data from the target process
	PVOID pMemory = ExAllocatePoolWithTag(NonPagedPoolNx, szBufferSize, 'tag');
	if (!pMemory)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(pMemory, szBufferSize);

	KAPC_STATE kApc = { 0 };
	KeStackAttachProcess(pEprocess, &kApc);

	// Switch to the target process' CR3 and read memory
	ULONG64 ulTargetCr3 = *(PULONG64)((PUCHAR)pEprocess + 0x28);
	ULONG64 ulCurrentCr3 = __readcr3();

	KeEnterCriticalRegion();
	_disable();
	__writecr3(ulTargetCr3);

	if (MmIsAddressValid(pBaseAddress) && MmIsAddressValid((PVOID)((ULONG64)pBaseAddress + szBufferSize)))
	{
		memcpy(pMemory, pBaseAddress, szBufferSize);
		ntStatus = STATUS_SUCCESS;
	}
	else
	{
		ntStatus = STATUS_ACCESS_VIOLATION;
	}

	_enable();
	__writecr3(ulCurrentCr3);
	KeLeaveCriticalRegion();

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);

	// Copy the data to the user buffer
	if (NT_SUCCESS(ntStatus))
	{
		memcpy(pBuffer, pMemory, szBufferSize);
	}

	ExFreePoolWithTag(pMemory, 'tag');
	return ntStatus;
}

NTSTATUS ReadProcessMemory(HANDLE pid, PVOID address, PVOID bufferaddress, SIZE_T bufferSize)
{
	// Lookup the target process by ID
	PEPROCESS targetProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error 0x1.\n");
		return FALSE;
	}

	// Check if the current process is valid
	PEPROCESS currentProcess = IoGetCurrentProcess();
	if (!currentProcess)
	{
		DbgPrint("Error 0x2");
		ObDereferenceObject(targetProcess);
		return FALSE;
	}

	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(targetProcess, &stack);

	// Allocate memory and copy data from the target process
	PVOID pMemory = ExAllocatePoolWithTag(NonPagedPoolNx, bufferSize, 'tag');
	if (!pMemory)
	{
		KeUnstackDetachProcess(&stack);
		ObDereferenceObject(targetProcess);
		return FALSE;
	}

	__try
	{
		ProbeForRead(address, (SIZE_T)bufferSize, (ULONG)1);
		RtlZeroMemory(pMemory, bufferSize);
		memcpy(pMemory, address, (SIZE_T)bufferSize);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Read Memory Faild.\n");
		ExFreePoolWithTag(pMemory, 'tag');
		KeUnstackDetachProcess(&stack);
		ObDereferenceObject(targetProcess);
		return FALSE;
	}

	KeUnstackDetachProcess(&stack);

	__try
	{
		memcpy(bufferaddress, pMemory, bufferSize);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Copy Memory Faild.\n");
		ExFreePoolWithTag(pMemory, 'tag');
		ObDereferenceObject(targetProcess);
		return FALSE;
	}

	DbgPrint("Process Id: %d Address: %p BufferSize %x", pid, address, bufferSize);

	ExFreePoolWithTag(pMemory, 'tag');
	ObDereferenceObject(targetProcess);
	return TRUE;
}


NTSTATUS KernelReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID Targetaddress, SIZE_T Size) {

	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		Targetaddress, Size, KernelMode, &Bytes)))
	{
		return STATUS_SUCCESS;
	}
	return STATUS_ACCESS_DENIED;
}