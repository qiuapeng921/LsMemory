#include<ntifs.h>
#include"标头.h"
#include "CR0读写.h"

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

NTSTATUS CROReadMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
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

NTSTATUS CR0WriteMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
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

	SIZE_T retNum = 0;
	//直接先写一次
	ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
	if (NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(pEprocess);
		return ntStatus;

	}
	//没有写成功
	PEPROCESS pCurrentEprocess = IoGetCurrentProcess();
	KeStackAttachProcess(pEprocess, &kApc);
	PVOID pvAddr = pBaseAddress;
	SIZE_T szSize = szBufferSize;
	ULONG ulAttr = 0;
	// ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, PAGE_EXECUTE_READWRITE, &ulAttr);
	if (NT_SUCCESS(ntStatus))
	{
		SIZE_T retNum = 0;
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		// NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, ulAttr, &ulAttr);
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);
	if (!NT_SUCCESS(ntStatus))
	{
		//关中断
		_disable();
		//读取CR0
		ULONG64 ulRegCr0 = __readcr0();
		__writecr0(ulRegCr0 & (~0x10000));//关保护
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		__writecr0(ulRegCr0);
		_enable();
	}
	return ntStatus;
}

NTSTATUS WriteMemory_MDL(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, IN PVOID Buffer)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	PVOID temp_buff = NULL;

	if ((ULONG64)BaseAddress <= 0x10000 || (ULONG64)BaseAddress > 0x7fffffffffff)  //判断写入地址是否有效
	{
		DbgPrint("[+]MmIsAddressValid:Fail\n");
		return STATUS_UNSUCCESSFUL;
	}

	temp_buff = ExAllocatePool(NonPagedPool, Length);  //申请内核地址
	if (temp_buff == NULL)
	{
		DbgPrint("[+]ExAllocatePool:Fail\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(temp_buff, Buffer, Length);//把要写入的数据存在内核地址里
	Status = PsLookupProcessByProcessId((HANDLE)ProcessPid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[+]PsLookupProcessByProcessId:Fail\n");
		ExFreePool(temp_buff); //释放内核地址
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(pEProcess, &ApcState);

	pMdl = MmCreateMdl(NULL, BaseAddress, Length);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pNewAddress = MmMapLockedPages(pMdl, KernelMode); //锁定MDL页面
		if (pNewAddress)
		{
			RtlCopyMemory(pNewAddress, temp_buff, Length);
			MmUnmapLockedPages(pNewAddress, pMdl); //解锁MDL页面
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_UNSUCCESSFUL;
		}
		IoFreeMdl(pMdl);//释放创建的MDL
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	ExFreePool(temp_buff); //释放内核地址
	return Status;
}

NTSTATUS ReadMemory_MDL(HANDLE pid, PVOID address, PVOID bufferaddress, SIZE_T BufferSize)
{
	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pMemory = ExAllocatePool(NonPagedPool, BufferSize);
	RtlZeroMemory(&pMemory, BufferSize);
	process = IoGetCurrentProcess();
	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error 0x1\n");
		return FALSE;
	}

	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(process, &stack);
	PMDL mdl = NULL;

	mdl = MmCreateMdl(NULL, address, 4);
	if (mdl == NULL)
	{
		DbgPrint("Error 0x1\n");
		return FALSE;
	}

	MmBuildMdlForNonPagedPool(mdl);

	__try
	{
		pMemory = MmMapLockedPages(mdl, KernelMode);
	}
	__except (1)
	{

		DbgPrint("Memory mapping failed.\n");

		IoFreeMdl(mdl);
		ObDereferenceObject(process);
		KeUnstackDetachProcess(&stack);
		return FALSE;
	}

	RtlCopyMemory(pMemory, &bufferaddress, BufferSize);
	DbgPrint("进程ID:%d 地址:%x 写入数据:%d", pid, address, *(PVOID*)pMemory);
	IoFreeMdl(mdl);
	MmUnmapLockedPages(pMemory, mdl);
	ObDereferenceObject(process);
	KeUnstackDetachProcess(&stack);

	return TRUE;
}