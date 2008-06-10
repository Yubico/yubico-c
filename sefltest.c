/* pof-test.c --- Self-tests for authentication token functions.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006, 2007, 2008 Yubico AB
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

#include <pof.h>
#include <stdio.h>

int
main (void)
{
  uint8_t buf[1024];
  uint8_t key[16 + 1];
  size_t i;

  pof_modhex_encode(buf, (uint8_t*) "test", 4);
  printf ("modhex-encode(\"test\") = %s\n", buf);
  if (strcmp ((char*)buf, "ifhgieif") != 0)
    {
      printf ("ModHex failure\n");
      return 1;
    }
  printf ("Modhex-1 success\n");

  printf ("modhex-decode(\"%s\") = ", buf);
  pof_modhex_decode(buf, buf, strlen ((char*)buf));
  printf ("%.*s\n", 4, buf);
  if (memcmp (buf, "test", 4) != 0)
    {
      printf ("ModHex failure\n");
      return 1;
    }
  printf ("Modhex-2 success\n");

  strcpy ((char*)buf, "0123456789abcdef");
  strcpy ((char*)key, "abcdef0123456789");
  printf ("aes-decrypt (data=%s, key=%s)\n => ", buf, key);
  pof_aes_decrypt (buf, key);
  for (i = 0; i < 16; i++)
    printf ("%02x", buf[i]);
  printf("\n");

  if (memcmp (buf, "\x83\x8a\x46\x7f\x34\x63\x95\x51\x75\x5b\xd3\x2a\x4a\x2f\x15\xe1", 16) != 0)
    {
      printf ("AES failure\n");
      return 1;
    }
  printf ("AES-1 success\n");

  printf ("\nAll tests successful\n");
  return 0;
}
