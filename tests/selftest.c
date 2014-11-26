/* yubikey-test.c --- Self-tests for authentication token functions.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006-2014 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <yubikey.h>
#include <stdio.h>
#include <assert.h>

static void
modhex_test1 (void)
{
  char buf[1024];
  char buf2[1024];

  yubikey_modhex_encode (buf, "test", 4);
  printf ("modhex-encode(\"test\") = %s\n", buf);
  assert (strcmp (buf, "ifhgieif") == 0);
  printf ("Modhex-1.1 success\n");

  printf ("modhex-decode(\"%s\") = ", buf);
  yubikey_modhex_decode (buf2, buf, sizeof (buf2));
  printf ("%.*s\n", 4, buf2);
  assert (memcmp (buf2, "test", 4) == 0);
  printf ("Modhex-1.2 success\n");
}

static void
modhex_test2 (void)
{
  char buf[1024];
  int rc;

  strcpy (buf, "cbdefghijklnrtuv");
  rc = yubikey_modhex_p (buf);
  printf ("modhex-p(\"%s\") = %d\n", buf, rc);
  assert (rc == 1);
  printf ("Modhex-2 success\n");
}

static void
modhex_test3 (void)
{
  char buf[1024];
  int rc;

  strcpy (buf, "cbdefghijklnrtuv");
  rc = yubikey_modhex_p (buf);
  printf ("modhex-p(\"%s\") = %d\n", buf, rc);
  assert (rc == 1);
  printf ("Modhex-3 success\n");
}

static void
hex_test1 (void)
{
  char buf[1024];
  int rc;

  strcpy (buf, "0123Xabc");
  rc = yubikey_hex_p (buf);
  printf ("hex-p(\"%s\") = %d\n", buf, rc);
  assert (rc == 0);
  printf ("Hex-1 success\n");
}

static void
hex_test2 (void)
{
  char buf[1024];
  char buf2[1024];

  yubikey_hex_encode (buf, "test", 4);
  printf ("hex-encode(\"test\") = %s\n", buf);
  assert (strcmp (buf, "74657374") == 0);
  printf ("Hex-2.1 success\n");

  printf ("hex-decode(\"%s\") = ", buf);
  yubikey_hex_decode (buf2, buf, sizeof (buf2));
  printf ("%.*s\n", 4, buf2);
  assert (memcmp (buf2, "test", 4) == 0);
  printf ("Hex-2.2 success\n");
}

static void
hex_test3 (void)
{
  char buf[1024];
  int rc;

  strcpy (buf, "0123456789abcdef");
  rc = yubikey_hex_p (buf);
  printf ("hex-p(\"%s\") = %d\n", buf, rc);
  assert (rc == 1);
  printf ("Hex-3 success\n");
}

static void
hex_test4 (void)
{
  char buf[1024];
  int rc;

  strcpy (buf, "0123Xabc");
  rc = yubikey_hex_p (buf);
  printf ("hex-p(\"%s\") = %d\n", buf, rc);
  assert (rc == 0);
  printf ("Hex-4 success\n");
}

static void
hex_test5 (void)
{
  char buf[1024];
  char buf2[1024];
  char cmp[1024];

  strcpy (buf, "a2c2a");
  memset (buf2, 0, sizeof (buf2));
  yubikey_hex_decode (buf2, buf, sizeof (buf2));
  printf ("hex-decode(\"%s\") = %x%x%x\n", buf, buf2[0], buf2[1], buf2[2]);
  cmp[0] = 0xa;
  cmp[1] = 0x2c;
  cmp[2] = 0x2a;
  assert (memcmp (buf2, cmp, 3) == 0);
  printf ("Hex-5 success\n");
}

static void
aes_test1 (void)
{
  size_t i;
  uint8_t buf[1024];
  uint8_t key[16 + 1];

  memcpy (buf, "0123456789abcdef\0", 17);
  memcpy (key, "abcdef0123456789\0", 17);
  printf ("aes-decrypt (data=%s, key=%s)\n => ", (char *) buf, (char *) key);
  yubikey_aes_decrypt (buf, key);
  for (i = 0; i < 16; i++)
    printf ("%02x", buf[i] & 0xFF);
  printf ("\n");

  assert (memcmp (buf,
		  "\x83\x8a\x46\x7f\x34\x63\x95\x51"
		  "\x75\x5b\xd3\x2a\x4a\x2f\x15\xe1", 16) == 0);
  printf ("AES-1.1 success\n");

  yubikey_aes_encrypt (buf, key);
  assert (memcmp (buf, "0123456789abcdef", 16) == 0);
  printf ("AES-1.2 success\n");
}

static void
otp_test1 (void)
{
  yubikey_token_st tok;
  char out[1024];
  uint8_t key[16 + 1];

  /* Test OTP */

  memcpy ((void *) &tok,
	  "\x16\xe1\xe5\xd9\xd3\x99\x10\x04\x45\x20\x07\xe3\x02\x00\x00", 16);
  memcpy (key, "abcdef0123456789", 16);

  yubikey_generate ((void *) &tok, key, out);
  yubikey_parse ((uint8_t *) out, key, &tok);

  assert (memcmp (&tok,
		  "\x16\xe1\xe5\xd9\xd3\x99\x10\x04\x45\x20\x07\xe3\x02\x00\x00",
		  16) == 0);
  printf ("OTP-1 success\n");
}

static void
crc_test1 (void)
{
  unsigned char buf[] = { 0, 1, 2, 3, 4 };
  uint16_t crc = yubikey_crc16 (buf, sizeof (buf));
  assert (crc == 62919);
  printf ("CRC-1 success\n");
}

static void
crc_test2 (void)
{
  unsigned char buf[] = { 0xfe };
  uint16_t crc = yubikey_crc16 (buf, sizeof (buf));
  assert (crc == 4470);
  printf ("CRC-2 success\n");
}

static void
crc_test3 (void)
{
  unsigned char buf[] = { 0x55, 0xaa, 0, 0xff };
  uint16_t crc = yubikey_crc16 (buf, sizeof (buf));
  assert (crc == 52149);
  printf ("CRC-3 success\n");
}

static void
crc_test4 (void)
{
  unsigned char buf[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x30, 0x75, 0x00, 0x09, 0x3d, 0xfa, 0x60, 0xea
  };
  uint16_t crc = yubikey_crc16 (buf, sizeof (buf));
  assert (crc == 35339);
  printf ("CRC-4 success\n");
}

int
main (void)
{
  modhex_test1 ();
  modhex_test2 ();
  modhex_test3 ();
  hex_test1 ();
  hex_test2 ();
  hex_test3 ();
  hex_test4 ();
  hex_test5 ();
  aes_test1 ();
  otp_test1 ();
  crc_test1 ();
  crc_test2 ();
  crc_test3 ();
  crc_test4 ();

  return 0;
}
