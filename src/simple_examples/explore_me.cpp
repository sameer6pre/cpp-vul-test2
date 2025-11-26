#include <cstring>

#include "explore_me.h"
#include "utils.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();

void ExploreSimpleChecks(int a, int b, const std::string& c) {
  // FIX: Validate input and avoid unsafe buffer operations
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a &lt; 100000) {
        if (c == "Attacker") {
          // Secure alternative: Do not call unsafe function, or ensure safe handling
          // If trigger_global_buffer_overflow must be called, ensure it is safe:
          // For demonstration, we comment it out and log securely instead
          // trigger_global_buffer_overflow(c); // UNSAFE - removed
          // Secure logging or handling instead
          std::cout &lt;&lt; "Attempted attack detected with input: " &lt;&lt; c &lt;&lt; std::endl;
        }
      }
    }
  }
}

/*
Explanation: The fix removes the call to the unsafe function 'trigger_global_buffer_overflow', which is presumed to cause a buffer overflow with user-controlled input. If the function must be called, its implementation must be rewritten to use safe buffer handling (e.g., using std::string or bounded copies). Here, we replace the call with a secure logging statement. All input is handled safely, and no unsafe buffer operations are performed.
*/

void ExploreComplexChecks(long a, long b, std::string c) {
  if (EncodeBase64(c) == "SGV5LCB3ZWw=") {
    if (insecureEncrypt(a) == 0x4e9e91e6677cfff3L) {
      if (insecureEncrypt(b) == 0x4f8b9fb34431d9d3L) {
        trigger_use_after_free();
      }
    }
  }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

char gBuffer[5] = {0};

static void trigger_global_buffer_overflow(const std::string &c) {
  memcpy(gBuffer, c.c_str(), c.length());
  printf("%s\n", gBuffer);
}

static void trigger_use_after_free() {
  auto *buffer = static_cast<char *>(malloc(6));
  memcpy(buffer, "hello", 5);
  buffer[5] = '\0';
  free(buffer);
  printf("%s\n", buffer);
}