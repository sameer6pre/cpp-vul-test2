#include <cstring>

#include "explore_me.h"
#include "utils.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();

void ExploreSimpleChecks(int a, int b, std::string c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "Attacker") {
          trigger_global_buffer_overflow(c);
        }
      }
    }
  }
}

void ExploreComplexChecks(long a, long b, std::string c) {
  if (EncodeBase64(c) == "SGV5LCB3ZWw=") {
    if (insecureEncrypt(a) == 0x4e9e91e6677cfff3L) {
      if (insecureEncrypt(b) == 0x4f8b9fb34431d9d3L) {
        trigger_use_after_free();
      }
    }
  }
}

#include <openssl/aes.h>
#include <cstring>

static void secureEncrypt(const unsigned char* input, unsigned char* output, const unsigned char* key) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey);
    AES_encrypt(input, output, &encryptKey);
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