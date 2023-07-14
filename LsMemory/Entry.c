#include <ntifs.h>

#include "Constant.h"
#include "ReadMemory.h"
#include "WriteMemory.h"
#include "GetModuleBase.h"

// 初始化驱动句柄
NTSTATUS InitDeviceSymbolic(PDRIVER_OBJECT Driver) {
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pdeojb = { 0 };

	status = IoCreateDevice(Driver, 0, &usDeivceName, FILE_DEVICE_UNKNOWN, 0, 0, &pdeojb);

	if (!NT_SUCCESS(status)) {

		KdPrint(("[LsMemory]:failed to create device\n"));

		return status;

	}

	status = IoCreateSymbolicLink(&usSymbolicName, &usDeivceName);

	if (!NT_SUCCESS(status)) {

		IoDeleteDevice(pdeojb);

		KdPrint(("[LsMemory]:failed to create symbolic name\n"));

		return status;
	}

	KdPrint(("[LsMemory]:Create Link Success\n"));

	return status;

}

// 转发创建关闭
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


// Ioc通讯
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  IoStackLocation = NULL;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataLength = 0, OutputDataLength = 0, IoControlCode = 0;

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	InputDataLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	OutputDataLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;


    switch (IoControlCode) {
    case IoctlCard:
        KdPrint(("卡密验证!\n"));
        break;
    case IoctlReadWriteMod:
        KdPrint(("读写模式!\n"));
        break;
    case IoctlModuleAddress:
        KdPrint(("取模块地址!\n"));
        break;
    case IoctlModuleFuncAddress:
        KdPrint(("取模块函数地址!\n"));
        break;
    case IoctlRead:
        KdPrint(("读取数据!\n"));
		// ReadMemory1(((PDataStruct)InputData)->ProcessPid, ((PDataStruct)InputData)->TargetAddress, ((PDataStruct)InputData)->Length, OutputData);
		Status = STATUS_SUCCESS;
        break;
    case IoctlWrite:
        KdPrint(("写入数据!\n"));
		WriteMemory(((PDataStruct)InputData)->ProcessPid, ((PDataStruct)InputData)->TargetAddress, ((PDataStruct)InputData)->Length, ((PDataStruct)InputData)->Buffer);
		Status = STATUS_SUCCESS;
        break;
    case IoctlAlloc:
        KdPrint(("申请内存!\n"));
        break;
    case IoctlFree:
        KdPrint(("释放内存!\n"));
        break;
    case IoctlHiddenProcessOn:
        KdPrint(("隐藏进程-开启!\n"));
        break;
    case IoctlHiddenProcessOff:
        KdPrint(("隐藏进程-关闭!\n"));
        break;
    case IoctlProtectProcessOn:
        KdPrint(("保护进程-开启!\n"));
        break;
    case IoctlProtectProcessOff:
        KdPrint(("保护进程-关闭!\n"));
        break;
    default:
        KdPrint(("无效的 IOCTL 代码: 0x%X\n", IoControlCode));
		Status = STATUS_UNSUCCESSFUL;
        break;
	}


	pIrp->IoStatus.Information = 0;
	if (Status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = OutputDataLength;
	}

	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}

// 驱动卸载
void DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("[LsMemory]:Unload Successly\r\n"));
	IoDeleteSymbolicLink(&usSymbolicName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

// 驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("[LsMemory]:Driver Load!\n"));

	pDrvObj->DriverUnload = DriverUnload;

	status = InitDeviceSymbolic(pDrvObj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	pDrvObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

	return status;
}