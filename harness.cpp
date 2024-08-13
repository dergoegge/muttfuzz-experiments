#include "FuzzedDataProvider.h"
#include "bitcoinconsensus.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <sys/shm.h>
#include <unistd.h>

uint8_t *characterization_buf = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  if (const char *shmid = getenv("SEMSAN_CHARACTERIZATION_SHMEM_ID")) {
    characterization_buf = (uint8_t *)shmat(atoi(shmid), NULL, 0);
    assert(characterization_buf);
    memset(characterization_buf, 0, 32);
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider{data, size};

  auto spk = fuzzed_data_provider.ConsumeRandomLengthString(); // scriptPubKey
  auto tx = fuzzed_data_provider.ConsumeRandomLengthString();  // txTo

  // p2sh | der | nulldummy | checklocktimeverify | checksequenceverify |
  // witness
  int flags = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 9) | (1 << 10) | (1 << 11);

  bitcoinconsensus_error err;
  bool ok = bitcoinconsensus_verify_script_with_amount(
      (const unsigned char *)spk.data(), spk.size(), /*amount=*/-1,
      (const unsigned char *)tx.data(), tx.size(), /*nIn=*/0, flags, &err);

  if (characterization_buf) {
    characterization_buf[0] = (uint8_t)ok;
  }

  return 0;
}
