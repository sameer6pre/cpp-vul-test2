
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto_1.h"
#include "gps_1.h"
#include "key_management_1.h"
#include "time_1.h"

#ifdef __cplusplus
}
#endif

static FuzzedDataProvider *gFDP;

// This function received the fuzzer generated data from the fuzz target.
// It needs to be called at the beginning of the LLVMFuzzerTestOneInput
// function.
void SetFDP(FuzzedDataProvider *fuzzed_data_provider) {
  gFDP = fuzzed_data_provider;
}

FuzzedDataProvider *GetFDP() { return gFDP; }

// Wrapper function for FuzzedDataProvider.h
// Writes |num_bytes| of input data to the given destination pointer. If there
// is not enough data left, writes all remaining bytes and fills the rest with
// zeros. Return value is the number of bytes written.
void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes) {
  if (destination != nullptr) {
    size_t num_consumed_bytes = GetFDP()->ConsumeData(destination, num_bytes);
    if (num_bytes > num_consumed_bytes) {
      size_t num_zero_bytes = num_bytes - num_consumed_bytes;
      std::memset((char *)destination + num_consumed_bytes, 0, num_zero_bytes);
    }
  }
}

#ifdef __cplusplus
extern "C" {
#endif

int driver_get_current_time() {
  int cifuzz_var_0 = GetFDP()->ConsumeIntegral<int>();
  return cifuzz_var_0;
}

uint8_t GPS_driver_obtain_current_position(uint8_t *position_as_bytes,
                                           uint8_t *hmac_as_bytes) {
  unsigned int position_as_bytes_length = 12;
  ConsumeDataAndFillRestWithZeros((void *)position_as_bytes,
                                  position_as_bytes_length);
  unsigned int hmac_as_bytes_length = 64;
  ConsumeDataAndFillRestWithZeros((void *)hmac_as_bytes, hmac_as_bytes_length);
  uint8_t cifuzz_var_1 = GetFDP()->ConsumeIntegral<uint8_t>();
  return cifuzz_var_1;
}

uint8_t HSM_get_random_byte() {
  // FIX: Use a cryptographically secure random number generator
  // On POSIX systems, use getrandom() or /dev/urandom; on Windows, use BCryptGenRandom or CryptGenRandom.
  // Here is a portable C++11+ solution using &lt;random> as a fallback, but for true cryptographic security, use platform APIs.
  #if defined(_WIN32)
    #include &lt;windows.h>
    #include &lt;bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    uint8_t byte = 0;
    if (BCryptGenRandom(NULL, &byte, sizeof(byte), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
      // Handle error securely (abort, log, etc.)
      abort();
    }
    return byte;
  #elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
    #include &lt;unistd.h>
    #include &lt;sys/random.h>
    uint8_t byte = 0;
    ssize_t res = getrandom(&byte, sizeof(byte), 0);
    if (res != sizeof(byte)) {
      // Handle error securely (abort, log, etc.)
      abort();
    }
    return byte;
  #else
    // Fallback: Use C++11 random_device (not guaranteed to be cryptographically secure on all platforms)
    #include &lt;random>
    std::random_device rd;
    return static_cast&lt;uint8_t>(rd());
  #endif
}

// This fix ensures that HSM_get_random_byte uses a cryptographically secure random number generator appropriate for the platform. It avoids any use of fuzzing or test-only utilities, and aborts securely if randomness cannot be obtained. This is robust for production use and aligns with best practices for generating random bytes for security-sensitive operations.

uint8_t third_party_library_calc_hmac(const uint8_t *message, int len,
                                      const char *key, const char *nonce,
                                      uint8_t *hmac) {
  unsigned int hmac_length = 64;
  ConsumeDataAndFillRestWithZeros((void *)hmac, hmac_length);
  uint8_t cifuzz_var_3 = GetFDP()->ConsumeIntegral<uint8_t>();
  return cifuzz_var_3;
}

#ifdef __cplusplus
}
#endif
