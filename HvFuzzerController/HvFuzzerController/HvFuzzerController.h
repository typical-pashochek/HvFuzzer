#ifndef HVFUZZERCONTROLLER_H
#define HVFUZZERCONTROLLER_H

#include <string>
#include <stdexcept>
#include <windows.h>
#include "../../common/types.h"


class HvFuzzerController
{
public:
    HvFuzzerController(const std::string& fuzzerName, const std::string& fuzzerPath);
    ~HvFuzzerController();

    void loadFuzzer();
    void unloadFuzzer();
    void connectToFuzzer();
    void cpuid(PCPU_REG_32 pCpuInfo, int functonId);
    void msrRead(PULONG pMsrData, int reg);
    UINT32 hypercall(PHYPERCALL_DATA pInputBuf, PCPU_REG_64 pOutputBuf);

private:
    std::string fuzzerName;
    std::string fuzzerPath;
    HANDLE fuzzerHandle;

    std::string getServiceKeyName() const;
    void createService();
    void deleteService();
};

#endif // HVFUZZERCONTROLLER_H
