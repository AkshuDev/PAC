#include <stdlib.h>
#include <stdio.h>
#include <string.h>

inline static char* strndup(const char* src, size_t size) {
    size_t len = strnlen(src, size); // Use strnlen to avoid reading past 'size'
    char* new_str = malloc(len + 1);
    if (new_str) {
        memcpy(new_str, src, len);
        new_str[len] = '\\0';
    }
    return new_str;
}
