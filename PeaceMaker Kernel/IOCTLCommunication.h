/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "DetectionLogic.h"
#include "ImageFilter.h"
#include "ObjectFilter.h"

typedef class IOCTLCommunication
{
	static PDRIVER_OBJECT DriverObject;
	static PDETECTION_LOGIC Detector;
	static PIMAGE_FILTER ImageProcessFilter;
	static POBJECT_FILTER ObjectMonitor;

	NTSTATUS InitializeDriverIOCTL(VOID);
	VOID UninitializeDriverIOCTL(VOID);

	static NTSTATUS IOCTLCreateClose(
		_In_ PDEVICE_OBJECT DeviceObject,
		_In_ PIRP Irp
		);
	static NTSTATUS IOCTLDeviceControl(
		_In_ PDEVICE_OBJECT DeviceObject,
		_In_ PIRP Irp
		);

public:
	IOCTLCommunication(
		_In_ PDRIVER_OBJECT Driver,
		_In_ PUNICODE_STRING RegistryPath,
		_In_ PFLT_FILTER_UNLOAD_CALLBACK UnloadRoutine OPTIONAL,
		_Inout_ NTSTATUS* InitializeStatus
		);
	~IOCTLCommunication(VOID);
} IOCTL_COMMUNICATION, *PIOCTL_COMMUNICATION;

#define DETECTION_LOGIC_TAG 'lDmP'
#define IMAGE_FILTER_TAG 'fImP'
#define OBJECT_FILTER_TAG 'fOmP'