#include "HvFuzzerController/HvFuzzerController.h"
#include "FuzzInputParser/FuzzInputParser.h"
#include <iostream>

int main() 
{
    try
    {
        HvFuzzerController hvFuzzerController("HvFuzzer", "HvFuzzer.sys");
        CPU_REG_32 cpuInfo;

        hvFuzzerController.connectToFuzzer();

        hvFuzzerController.cpuid(&cpuInfo, 0x0);
        printf("[!] Vendor ID: %.4s%.4s%.4s\r\n",
            (CHAR*)&cpuInfo.ebx,
            (CHAR*)&cpuInfo.edx,
            (CHAR*)&cpuInfo.ecx);

        ULONG msrData;
        int reg = 0x40000020;
        hvFuzzerController.msrRead(&msrData, reg);
        printf("[+] MSR [0x%08x] = 0x%08x\r\n", reg, msrData);

        CPU_REG_64 regsOut = { 0 };
        CPU_REG_64 inRegs = { 0 };
        HV_X64_HYPERCALL_INPUT hvCallInput = { 0 };
        HYPERCALL_DATA hypercallData = { 0 };

        FuzzInputParser fuzzInputParser("hypercall_cases.txt");

        int counter = 0;
        RtlZeroMemory(&hypercallData, sizeof(HYPERCALL_DATA));
        while (fuzzInputParser.hasMoreArgs())
        {
            fuzzInputParser.getNextArgs(hypercallData);
            UINT32 retValue = hvFuzzerController.hypercall(&hypercallData, &regsOut);
            counter++;
            std::cout << "\rCase " << counter << ": " << "call_code = " << std::hex << hypercallData.hypercallInput.callCode << " ret value = " << regsOut.rax << std::flush;
        }


    }
    catch (std::exception e)
    {
        std::cout << e.what();
    }

    return 0;
}
