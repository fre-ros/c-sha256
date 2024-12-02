#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "sha256.h"

struct test_data
{
  const char *description;
  const char *msg;
  uint32_t expected_hash[8U];
};

static const struct test_data test_data[] =
{
  {
    .description = "Empty string",
    .msg = "",
    .expected_hash = {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855}
  },
  {
    .description = "The quick brown fox",
    .msg = "The quick brown fox jumps over the lazy dog.",
    .expected_hash = {0xef537f25, 0xc895bfa7, 0x82526529, 0xa9b63d97, 0xaa631564, 0xd5d789c2, 0xb765448c, 0x8635fb6c}
  },
  {
    .description = "Lorem ipsum",
    .msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt "
           "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
           "laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in "
           "voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat "
           "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
    .expected_hash = {0x2d8c2f6d, 0x978ca217, 0x12b5f6de, 0x36c9d31f, 0xa8e96a4f, 0xa5d8ff8b, 0x188dfb9, 0xe7c171bb}
  },
  {
    .description = "Long random data",
    .msg = "PKPYS50WE4IJ1TSETOBVTC3B6MIE5WAB71VUM7ZCTGA8KXCETDXU1VWYPWN089KODINRIQW78D5PEO41U0JX61H1WJXH"
           "Q91A8S41WA7BU5AIFP9EHHJMC9Q6T814JNTKQU8NJ347558L124DSLYWC4FHPEDJLS0B42A6SA35P7MN7RDDJ65QYDFT"
           "XGHYFJ5JZF9D5VJQ7YHN03X259IVUGV7ARGK2KNX418XWYKOHXG3X861FXVSKLNP8BVNZ5HRHJ1KR7R8TH8XIX0TNM6A"
           "5K8KGGC3E338XDSJI3YTHGZ18CL567SC9UQL5ZIHUZ7M3WRAYM9TXB30CQ0C2ZVEG23LI8JLVG34JBKXQRLM1WW6MVMB"
           "TQUCGJVINAR5KE5M6HEJRJGZJEIISVK3GAVG4C0SSQO0BDEIKF8BCE2X8PLGI6CWJLDEPXI13M96RHAOV70CZVNO26YO"
           "DQBUBWGFGI3O3WG92GCXS0KMLVZEF47RZ5Q6T8MNCCTNXP9VJ46JAXBNYX55EDSXEJTUG8CD2JMFUIOJJ3K05S0ZILDU"
           "GRHOVOR3I1GBSHPZQNJRDW335WRKUI4JOH6ZD3HF5XMKULIP3VGDT1JNEQGE10UJENCDU7NVRRK2VLWNHWCOSV5D9TIF"
           "FVJ2IRJJ7WLJKF13COO7RLIZ3Z11P00SM68CL53H3LMNI4Q4X60B7DSHLNJY963JM9O1RUJ0UY6FAX0A4DYJLBX3SB42"
           "PTZOIWB5FF2HPPG71I4URLRY5QCFYVH9YUTXU2F2KKCJ9G66ESWF02F1VJL67CPRURZFYE3RZOBRYVSK3TYDU6ZIQPOS"
           "48PZF2GMH0SKEY891AHD2MA3CWJJR0QKTXL91KJ7488DKIRBS88AUOWOJJHV8GKXPTQXNK4LUW9T5E17Q200M0O9HW0D"
           "FHUH4BM4XAXC4RJMG8W9D9DV6DP3K4HZNT122LMZ067I6T0TWRV1A176RVP7NS80DLFWZC4UP07CZ7GNXKYGKW5Q1SGS"
           "WNMISFSLF1RX0I663EN976WJ8TTVC9SH07QGD7R8YBN6WIB917BNZWIB00DCO8X13LT5KAJODPZF226A0W7JLBQK63TK"
           "B9U7LAOO5DJ857GY2RJMEK2DXFYE4S1E506N3RNXB2PEYT7200RFY7PYSWBF8IHWQZMJUVYBVVJTD7MUTSKO03XTZJJM"
           "KOZ00JRGWGM98RUJQK1277EGVW44PZXHES4AIZJ1LOHQI0CBT9E5DOYG6LCUDUT9JB4VQIS5VTCFLTDHSSWWMGYHPNTS"
           "GNWRAY2GV38M20E3TQ6WZ0IP13592V9ZOT6ATNWUZ3MEXXYHX9SNI0PHT01HKYNCA2AAJ1N6KF86MEEIGICJ8Z1ED80Y"
           "W1YJDPTLOXF7HHVPF9QL9JJ8A34NO3E57929JN7UC2O",
    .expected_hash = {0x6126a2e3, 0x3478909f, 0x41bfbcbf, 0x4d018966, 0x675aa283, 0x431c4fb, 0x3935f55f, 0x3c0d3d2}
  },
};

static void sha256_test(const struct test_data *test)
{
  uint32_t hash[8U];
  sha256((uint8_t*)test->msg, strlen(test->msg), hash);
  assert(memcmp(hash, test->expected_hash, sizeof hash) == 0);
}

static void init_feed_finalize_test(const struct test_data *test)
{
  uint32_t hash[8U];

  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_feed(&ctx, (uint8_t*)test->msg, strlen(test->msg));
  sha256_finalize(&ctx, hash);

  assert(memcmp(hash, test->expected_hash, sizeof hash) == 0);
}

static void init_feed_finalize_chunked_test(const struct test_data *test)
{
  uint32_t hash[8U];

  struct sha256_ctx ctx;
  sha256_init(&ctx);

  size_t msg_len = strlen(test->msg);
  uint8_t *data = (uint8_t*)test->msg;

  for (size_t i = 0U; i< msg_len; i++)
  {
    sha256_feed(&ctx, &data[i], 1U);
  }

  sha256_finalize(&ctx, hash);

  assert(memcmp(hash, test->expected_hash, sizeof hash) == 0);
}

int main(void)
{
  puts("----- Running tests -----");
  for (size_t i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++)
  {
    printf("%s...", test_data[i].description);
    sha256_test(&test_data[i]);
    init_feed_finalize_test(&test_data[i]);
    init_feed_finalize_chunked_test(&test_data[i]);
    puts("OK");
  }
  return 0;
}
