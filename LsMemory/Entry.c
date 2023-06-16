#include <ntddk.h>

#include "Constant.h"


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

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0, code = 0, len = 0, size = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	KdPrint(("[LsMemory]:failed to create device\n"));

	switch (code) {
	case IOCTL_GET_SECTION_ADDRESS:
		KdPrint(("获取段地址!\n"));
		break;
	case IOCTL_WRITE_MEMORY:
		KdPrint(("写内存!\n"));
		break;
	case IOCTL_ALLOCATE_MEMORY:
		KdPrint(("申请内存!\n"));
		break;
	case IOCTL_FREE_MEMORY:
		KdPrint(("释放内存!\n"));
		break;
	default:
		KdPrint(("无效的 IOCTL 代码: 0x%X\n", code));
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("[LsMemory]:Unload Successly\r\n"));
	IoDeleteSymbolicLink(&usSymbolicName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

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

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	
	return status;
}