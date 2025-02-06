#include "HvFuzzerController.h"
#include <stdexcept>
#include <sstream>
#include <iostream>

HvFuzzerController::HvFuzzerController(const std::string& fuzzerName, const std::string& fuzzerPath)
    : fuzzerName(fuzzerName), fuzzerPath(fuzzerPath), fuzzerHandle(INVALID_HANDLE_VALUE)
{
}

HvFuzzerController::~HvFuzzerController()
{
    if (fuzzerHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(fuzzerHandle);
    }
}

void HvFuzzerController::loadFuzzer()
{
    createService();

    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager)
    {
        throw std::runtime_error("Failed to open Service Control Manager");
    }

    SC_HANDLE service = OpenServiceA(scManager, fuzzerName.c_str(), SERVICE_START);
    if (!service)
    {
        CloseServiceHandle(scManager);
        throw std::runtime_error("Failed to open service");
    }

    if (!StartService(service, 0, nullptr))
    {
        DWORD err = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
            throw std::runtime_error("Failed to start service");
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
}

void HvFuzzerController::unloadFuzzer()
{
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager)
    {
        throw std::runtime_error("Failed to open Service Control Manager");
    }

    SC_HANDLE service = OpenServiceA(scManager, fuzzerName.c_str(), SERVICE_STOP | DELETE);
    if (!service)
    {
        CloseServiceHandle(scManager);
        throw std::runtime_error("Failed to open service");
    }

    SERVICE_STATUS serviceStatus;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            throw std::runtime_error("Failed to stop service");
        }
    }

    deleteService();
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
}

void HvFuzzerController::connectToFuzzer()
{
    std::string devicePath = "\\\\.\\" + fuzzerName;
    fuzzerHandle = CreateFileA(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (fuzzerHandle == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("Failed to connect to fuzzer");
    }
}

void HvFuzzerController::cpuid(PCPU_REG_32 pCpuInfo, int functonId)
{
    BOOL    status = FALSE;
    DWORD   bytesRet = 0;

    status = DeviceIoControl(fuzzerHandle,
        IOCTL_CPUID,
        &functonId,
        sizeof(INT),
        pCpuInfo,
        sizeof(CPU_REG_32),
        &bytesRet,
        NULL);

    std::cout << status << '\n' << bytesRet;

    if (!status || bytesRet != sizeof(CPU_REG_32))
    {
        throw std::runtime_error("[-] ERR DeviceIoControl IOCTL_CPUID");
    }
}

void HvFuzzerController::msrRead(PULONG pMsrData, int reg)
{
    BOOL    status = FALSE;
    DWORD   bytesRet = 0;
    DWORD   outputBuf = NULL;

    status = DeviceIoControl(fuzzerHandle,
        IOCTL_MSR_READ,
        &reg,
        4,
        &outputBuf,
        4,
        &bytesRet,
        NULL);

    if (!status && bytesRet != 4)
    {
        throw std::runtime_error("[-] ERR DeviceIoControl IOCTL_MSR_READ");
    }

    *pMsrData = outputBuf;    
}

UINT32 HvFuzzerController::hypercall(PHYPERCALL_DATA pInputBuf, PCPU_REG_64 pOutputBuf)
{
    BOOL    status = FALSE;
    DWORD   bytesRet = 0;
    DWORD   outputBuf = NULL;

    status = DeviceIoControl(fuzzerHandle,
        IOCTL_HYPERCALL,
        pInputBuf,
        sizeof(HYPERCALL_DATA),
        pOutputBuf,
        sizeof(CPU_REG_64),
        &bytesRet,
        NULL);

    return status;
}


std::string HvFuzzerController::getServiceKeyName() const
{
    return "System\\CurrentControlSet\\Services\\" + fuzzerName;
}

void HvFuzzerController::createService()
{
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager)
    {
        throw std::runtime_error("Failed to open Service Control Manager");
    }

    SC_HANDLE service = CreateServiceA(
        scManager,
        fuzzerName.c_str(),
        fuzzerName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        fuzzerPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!service)
    {
        DWORD err = GetLastError();
        CloseServiceHandle(scManager);
        if (err != ERROR_SERVICE_EXISTS)
        {
            throw std::runtime_error("Failed to create service");
        }
    }
    else
    {
        CloseServiceHandle(service);
    }

    CloseServiceHandle(scManager);
}

void HvFuzzerController::deleteService()
{
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager)
    {
        throw std::runtime_error("Failed to open Service Control Manager");
    }

    SC_HANDLE service = OpenServiceA(scManager, fuzzerName.c_str(), DELETE);
    if (service)
    {
        if (!DeleteService(service))
        {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            throw std::runtime_error("Failed to delete service");
        }
        CloseServiceHandle(service);
    }

    CloseServiceHandle(scManager);
}
