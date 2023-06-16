﻿#include "ReadMemory.h"

NTSTATUS ReadDirect(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
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


	PVOID pMemory = ExAllocatePool(NonPagedPool, szBufferSize);
	RtlZeroMemory(pMemory, szBufferSize);
	KeStackAttachProcess(pEprocess, &kApc);
	ntStatus = STATUS_UNSUCCESSFUL;
	if (MmIsAddressValid(pBaseAddress) && MmIsAddressValid((PVOID)((ULONG64)pBaseAddress + szBufferSize)))
	{
		memcpy(pMemory, pBaseAddress, szBufferSize);
		ntStatus = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&kApc);
	if (NT_SUCCESS(ntStatus))
	{
		memcpy(pBuffer, pMemory, szBufferSize);
	}
	ObDereferenceObject(pEprocess);
	ExFreePool(pMemory);
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


	PVOID pMemory = ExAllocatePool(NonPagedPool, szBufferSize);
	RtlZeroMemory(pMemory, szBufferSize);
	ULONG64 ulTargetCr3 = *(PULONG64)((PUCHAR)pEprocess + 0x28);
	ULONG64 ulCurrentCr3 = __readcr3();
	KeEnterCriticalRegion();
	_disable();
	__writecr3(ulTargetCr3);
	ntStatus = STATUS_UNSUCCESSFUL;
	if (MmIsAddressValid(pBaseAddress) && MmIsAddressValid((PVOID)((ULONG64)pBaseAddress + szBufferSize)))
	{
		memcpy(pMemory, pBaseAddress, szBufferSize);
		ntStatus = STATUS_SUCCESS;
	}

	_enable();
	__writecr3(ulCurrentCr3);
	KeLeaveCriticalRegion();

	if (NT_SUCCESS(ntStatus))
	{
		memcpy(pBuffer, pMemory, szBufferSize);
	}
	ObDereferenceObject(pEprocess);
	ExFreePool(pMemory);
	return ntStatus;
}