/*
 * Copyright (C) 2020 Yubico AB - See COPYING
 */
#include <stdio.h>

#include "yubikey.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  /* libyubikey has 11 functions that require no state, lets
   * just hammer on them. Initial seeds can be extracted from
   * the unit tests, apply selftest.c.patch to unit test and run
   * it to generate initial seeds if not using the included corpus.
   */

  char buf[4096] = {0};
  char buf2[sizeof(buf) * 2 + 1]; /* hex encoded buf + \0 */
  /* - 2 below is one byte to choose action and one byte to keep
   * the buf array null terminated no matter what. */
  if (size > sizeof(buf) - 2 || !data || size <= 1) {
    return -1;
  }

  const char *ptr = data + 1;
  size -= 1;

  switch(data[0]) {
  case 1:
    yubikey_modhex_encode(buf2, ptr, size);
    break;
  case 2:
    memcpy(buf, ptr, size);
    yubikey_modhex_decode(buf2, buf, sizeof(buf2));
    break;
  case 3:
    memcpy(buf, ptr, size);
    yubikey_modhex_p(buf);
    break;
  case 4:
    memcpy(buf, ptr, size);
    yubikey_hex_p(buf);
    break;
  case 5:
    yubikey_hex_encode(buf2, ptr, size);
    break;
  case 6:
    memcpy(buf, ptr, size);
    yubikey_hex_decode(buf2, buf, sizeof(buf2));
    break;
  case 7:
    if (size > YUBIKEY_KEY_SIZE) {
      memcpy(buf, ptr, size);
      yubikey_aes_decrypt(buf + YUBIKEY_KEY_SIZE, buf);
    }
    break;
  case 8:
    if (size > YUBIKEY_KEY_SIZE) {
      memcpy(buf, ptr, size);
      yubikey_aes_encrypt(buf + YUBIKEY_KEY_SIZE, buf);
    }
    break;
  case 9:
    if (size > YUBIKEY_KEY_SIZE + sizeof(yubikey_token_st)) {
      yubikey_token_st st;
      memcpy((void*)&st, ptr + YUBIKEY_KEY_SIZE, sizeof(yubikey_token_st));
      yubikey_generate ((void*)&st, ptr, buf);
    }
    break;
  case 10:
#define TOKEN_HEX_LENGTH YUBIKEY_KEY_SIZE * 2
    if (size > (YUBIKEY_KEY_SIZE * 3) + sizeof(yubikey_token_st)) {
      yubikey_token_st st = {0};
      memcpy(buf, ptr, TOKEN_HEX_LENGTH);
      buf[TOKEN_HEX_LENGTH] = '\0';
      yubikey_parse ((const uint8_t*)buf, (void*)ptr + TOKEN_HEX_LENGTH, &st);
    }
    break;
  case 11:
    yubikey_crc16((const uint8_t*)ptr, size);
    break;
  }

  return 0;
}
