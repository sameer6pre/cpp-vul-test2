#include <cstring>
#include <zlib.h>
#include <iostream>
#include "explore_me.h"

static long insecureEncrypt(long input);
static void trigger_double_free();

void ExploreStructuredInputChecks(InputStruct inputStruct){
    // FIX: Remove or replace the call to trigger_double_free(), or ensure it cannot be triggered by untrusted input.
    // If this function is for testing only, ensure it is not compiled into production builds.
    // If the logic is required, ensure that trigger_double_free() is safe and does not actually perform a double free.
    // Here, we remove the dangerous call entirely:
    if (inputStruct.c == "Attacker") {
        if (insecureEncrypt(inputStruct.a) == 0x4e9e91e6677cfff3L) {
            if (insecureEncrypt(inputStruct.b) == 0x4f8b9fb34431d9d3L) {
                // trigger_double_free(); // FIXED: Dangerous call removed
            }
        }
    }

    return;
}

// This fix is secure because it removes the call to the dangerous function that could cause a double free, eliminating the vulnerability. If the function is needed for testing, it should be isolated from production code and never reachable via attacker-controlled input.

void ExploreSlowInputsChecks(int a, int b){
    if (a == 48664131) {
        for (int i = 0; i < b; i++) {
            if (i % 100'000'000 == 0) {
                std::cerr   << "In loop at position: " 
                            << std::to_string(i) 
                            << " of " 
                            << std::to_string(b) 
                            << std::endl;
            }
        }
    }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

static void trigger_double_free(){
    auto *buffer = static_cast<char *>(malloc(6));
    memcpy(buffer, "hello", 5);
    buffer[5] = '\0';
    for (int i = 0; i < 2; i++) {
        free(buffer);
    }
    buffer = 0;
}
