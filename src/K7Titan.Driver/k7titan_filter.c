/* K7 TITAN filesystem minifilter driver (scaffold).
 * Registers pre-create callbacks and forwards file paths to the
 * user-mode real-time protection service. */
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#ifndef IRP_MJ_OPERATION_END_OF_QUEUE
#define IRP_MJ_OPERATION_END_OF_QUEUE ((UCHAR)0x80)
#endif

#define K7TITAN_POOL_TAG 'TI7K'
#define K7TITAN_PORT_NAME L"\\K7TitanPort"

PFLT_FILTER g_FilterHandle = NULL;
PFLT_PORT g_ServerPort = NULL;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

static NTSTATUS K7TitanConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                               _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                               _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID* ConnectionPortCookie) {
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  UNREFERENCED_PARAMETER(ConnectionPortCookie);
  g_ServerPort = ClientPort;
  return STATUS_SUCCESS;
}

static VOID K7TitanDisconnect(_In_opt_ PVOID ConnectionCookie) {
  UNREFERENCED_PARAMETER(ConnectionCookie);
  if (g_ServerPort) {
    FltCloseClientPort(g_FilterHandle, &g_ServerPort);
    g_ServerPort = NULL;
  }
}

static FLT_PREOP_CALLBACK_STATUS K7TitanPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                                                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                  _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(CompletionContext);
  if (Data->RequestorMode == KernelMode) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, K7TitanPreCreate, NULL},
    {IRP_MJ_OPERATION_END_OF_QUEUE, 0, NULL, NULL}};

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    NULL, /* K7TitanUnload */
    NULL, /* K7TitanInstanceSetup */
    NULL, /* K7TitanInstanceQueryTeardown */
    NULL, /* K7TitanInstanceTeardownStart */
    NULL, /* K7TitanInstanceTeardownComplete */
    NULL, NULL, NULL, NULL, NULL};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  NTSTATUS status;
  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING name;

  status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  RtlInitUnicodeString(&name, K7TITAN_PORT_NAME);
  InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
  status = FltCreateCommunicationPort(g_FilterHandle, &g_ServerPort, &oa, NULL, K7TitanConnect,
                                      K7TitanDisconnect, NULL, 1);
  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;
    return status;
  }

  status = FltStartFiltering(g_FilterHandle);
  if (!NT_SUCCESS(status)) {
    FltCloseCommunicationPort(g_ServerPort);
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;
  }
  return status;
}
