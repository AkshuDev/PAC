#pragma once

#include <string.h>

enum Architecture {
    x86_64,
    ARM64,
    x86,
    PVCPU,
    UNKNOWN_ARCH,
};

enum Architecture archs_to_archenum(char* arch) {
    if (!arch) {
        return UNKNOWN_ARCH;
    }

    if (arch)   {    
        if (strcmp(arch, "x86_64") == 0) {
            return x86_64;
        } else if (strcmp(arch, "arm64") == 0) {
            return ARM64;
        } else if (strcmp(arch, "x86") == 0) {
            return x86;
        } else if (strcmp(arch, "pvcpu") == 0) {
            return PVCPU;
        } else {
            return UNKNOWN_ARCH;
        }
    }
    return UNKNOWN_ARCH;
}

void archenum_to_archs(enum Architecture arch, char* archs) {
    switch (arch) {
        case x86_64:
            memcpy(archs, "x86_64", 6);
            break;
        case x86:
            memcpy(archs, "x86", 3);
            break;
        case ARM64:
            memcpy(archs, "arm64", 5);
            break;
        case PVCPU:
            memcpy(archs, "pvcpu", 5);
            break;
        default:
            memcpy(archs, "unknown", 7);
            break;
    }
}