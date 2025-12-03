#include <cstring>
#include <zlib.h>
#include <iostream>
#include "explore_me.h"

static long insecureEncrypt(long input);
static void trigger_double_free();

void ExploreStructuredInputChecks(InputStruct inputStruct){
    // FIX: Remove or replace the call to trigger_double_free() with safe logic.
    // If this was for testing, ensure such dangerous code is not present in production.
    // If some action is needed here, implement it safely without double free.
    if (inputStruct.c == "Attacker") {
        if (insecureEncrypt(inputStruct.a) == 0x4e9e91e6677cfff3L) {
            if (insecureEncrypt(inputStruct.b) == 0x4f8b9fb34431d9d3L) {
                // trigger_double_free(); // REMOVED: Prevent double free vulnerability
                // Optionally, log or handle the event safely
            }
        }
    }

    return;
}
// FIX EXPLANATION: The call to trigger_double_free() is removed to eliminate the double free vulnerability. If this was intended for testing, such code must not be present in production. If some action is required here, it should be implemented in a way that does not risk memory safety.

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
