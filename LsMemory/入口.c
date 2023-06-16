#include <ntddk.h>

#include "��ͷ.h"
#include "��д.h"


NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	KdPrint(("���ȴ����ر�!\n"));
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
	ULONG i = 0, code = 0, len = 0, size = 0;
	PIO_STACK_LOCATION stack = NULL;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (code) {
	case IOCTL_GET_SECTION_ADDRESS:
		KdPrint(("��ȡ�ε�ַ!\n"));
		break;
	case IOCTL_WRITE_MEMORY:
		KdPrint(("д�ڴ�!\n"));
		break;
	case IOCTL_ALLOCATE_MEMORY:
		KdPrint(("�����ڴ�!\n"));
		break;
	case IOCTL_FREE_MEMORY:
		KdPrint(("�ͷ��ڴ�!\n"));
		break;
	case IOCTL_MAP_MEMORY:
		KdPrint(("ӳ���ڴ�!\n"));
		break;
	case IOCTL_UNMAP_MEMORY:
		KdPrint(("ȡ��ӳ���ڴ�!\n"));
		break;
	case IOCTL_DUMP_AND_RESET_CALLBACK:
		KdPrint(("ת�������ûص�!\n"));
		break;
	default:
		KdPrint(("��Ч�� IOCTL ����: 0x%X\n", code));
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

	KdPrint(("����ж��!\n"));
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("��������!\n"));
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	// pDrvObj->MajorFunction[IRP_MJ_CREATE] =
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}