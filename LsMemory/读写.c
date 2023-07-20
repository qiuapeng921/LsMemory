#include<ntifs.h>
#include"标头.h"
#include "读写.h"

NTSTATUS ReadMemory(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, OUT PVOID Buffer)
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

NTSTATUS WriteMemory(IN ULONG ProcessPid, IN  PVOID BaseAddress, IN ULONG Length, IN PVOID Buffer)
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


NTSTATUS ZwReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, DWORD32 nSize, PDWORD32 lpNumberOfBytesRead) {

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS FromProcess, ToProcess;


	status = ObReferenceObjectByHandle(hProcess, 0, *PsProcessType, KernelMode, (PVOID*)&FromProcess, 0);

	if (!NT_SUCCESS(status)) {

		KdPrint(("[Driver-CE]:unable to get object by handle errcode==0x%x\r\n", status));

		return status;
	}

	ToProcess = IoGetCurrentProcess();

	SIZE_T size = 0;

	status = MmCopyVirtualMemory(FromProcess, lpBaseAddress, ToProcess, lpBuffer, nSize, KernelMode, &size);


	if (!NT_SUCCESS(status)) {

		ObDereferenceObject(FromProcess);

		KdPrint(("[Driver-CE]:unable to read errcode==0x%x\r\n", status));

		return status;

	}

	if (MmIsAddressValid(lpNumberOfBytesRead)) {

		*(lpNumberOfBytesRead) = size;
	}

	ObDereferenceObject(FromProcess);
	return status;

}

NTSTATUS ZwWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, DWORD32 nSize, PDWORD32 lpNumberOfBytesWritten) {

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS ToProcess;


	status = ObReferenceObjectByHandle(hProcess, 0, *PsProcessType, KernelMode, (PVOID*)&ToProcess, 0);

	if (!NT_SUCCESS(status)) {
		KdPrint(("[Driver-CE]:unable to get object by handle errcode==0x%x\r\n", status));
		return status;
	}

	PEPROCESS FromProcess = IoGetCurrentProcess();

	SIZE_T size = 0;

	status = MmCopyVirtualMemory(FromProcess, lpBuffer, ToProcess, lpBaseAddress, nSize, KernelMode, &size);


	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(ToProcess);
		KdPrint(("[Driver-CE]:unable to read errcode==0x%x\r\n", status));
		return status;
	}

	if (MmIsAddressValid(lpNumberOfBytesWritten)) {
		*(lpNumberOfBytesWritten) = size;
	}

	ObDereferenceObject(ToProcess);
	return status;
}