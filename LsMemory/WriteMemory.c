#include"WriteMemory.h"

NTSTATUS NTAPI NtProtectVirtualMemory(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection) {

	typedef NTSTATUS(NTAPI* ZwProtectVirtualMemoryProc)(
		IN HANDLE               ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN OUT PULONG           NumberOfBytesToProtect,
		IN ULONG                NewAccessProtection,
		OUT PULONG              OldAccessProtection);

	static ZwProtectVirtualMemoryProc MyZwProtectVirtualMemory = NULL;
	if (!MyZwProtectVirtualMemory)
	{
		UNICODE_STRING usFunctionName = { 0 };
		RtlInitUnicodeString(&usFunctionName, L"ZwIsProcessInJob");
		PUCHAR puFunctionAddr = (PUCHAR)MmGetSystemRoutineAddress(&usFunctionName);
		if (puFunctionAddr)
		{
			puFunctionAddr += 20;
			for (size_t i = 0; i < 50; i++)
			{	//特征码搜索
				if (puFunctionAddr[i] == 0x48 && puFunctionAddr[i + 1] == 0x8b && puFunctionAddr[i + 2] == 0xc4) {
					MyZwProtectVirtualMemory = (ZwProtectVirtualMemoryProc)(puFunctionAddr + i);
					break;
				}
			}
		}
	}
	if (MyZwProtectVirtualMemory)
	{
		return MyZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

}


NTSTATUS WriteMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
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
	ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, PAGE_EXECUTE_READWRITE, &ulAttr);
	if (NT_SUCCESS(ntStatus))
	{
		SIZE_T retNum = 0;
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, ulAttr, &ulAttr);
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


NTSTATUS WriteProcessMemory(HANDLE pid, PVOID address, PVOID bufferaddress, SIZE_T BufferSize)
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


NTSTATUS KernelWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID Targetaddress, SIZE_T Size) {
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		Targetaddress, Size, KernelMode, &Bytes)))
	{
		return STATUS_SUCCESS;
	}
	return STATUS_ACCESS_DENIED;
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


NTSTATUS ReadMemory1(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, OUT PVOID Buffer)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	Status = PsLookupProcessByProcessId((HANDLE)ProcessPid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[+]PsLookupProcessByProcessId:Fail\n");
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(pEProcess, &ApcState);
	__try
	{
		ProbeForRead(BaseAddress, Length, 1);//校验是否可读
		RtlCopyMemory(Buffer, BaseAddress, Length); //读取进程数据
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;

		RtlZeroMemory(Buffer, Length); //清零返回值
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	return Status;
}

NTSTATUS WriteMemory1(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, IN PVOID Buffer)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };


	PVOID temp_buff = ExAllocatePool(NonPagedPool, Length);  //申请内核地址
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
	__try
	{
		ProbeForWrite(BaseAddress, Length, 1);//校验是否可写
		RtlCopyMemory(BaseAddress, temp_buff, Length); //读取进程数据
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_UNSUCCESSFUL;
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	ExFreePool(temp_buff); //释放内核地址
	return Status;
}


NTSTATUS AllocMemory(IN ULONG ProcessPid, IN SIZE_T Length, OUT PVOID Buffer)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	PVOID alloc_Address = NULL;
	SIZE_T alloc_lenght = Length;

	Status = PsLookupProcessByProcessId((HANDLE)ProcessPid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[+]PsLookupProcessByProcessId:Fail\n");
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(pEProcess, &ApcState);

	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &alloc_Address, 0, &alloc_lenght, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		*(PVOID*)Buffer = alloc_Address;
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	return Status;
}

NTSTATUS FreeMemory(IN ULONG ProcessPid, IN PVOID BaseAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	SIZE_T alloc_lenght = 0;

	Status = PsLookupProcessByProcessId((HANDLE)ProcessPid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[+]PsLookupProcessByProcessId:Fail\n");
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(pEProcess, &ApcState);

	Status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &alloc_lenght, MEM_RELEASE);

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	return Status;
}