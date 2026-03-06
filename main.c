#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <yara.h>

#include "scan.h"

/* -------------------------------------------------------------------------- */

#define dbg(...) fprintf(stderr, __VA_ARGS__)

#define check(expr) \
  if ((err = expr)) { \
    fprintf(stderr, "(%s:%d) %s() failed: %d\n", __FILE__, __LINE__, __func__, \
        err); \
    exit(EXIT_FAILURE); \
  }

/* -------------------------------------------------------------------------- */
/* types & forward declarations --------------------------------------------- */

struct iterator_context {
  uint8_t valid; /* 0 = consumed (already scanned or just invalid) */
  uint8_t last; /* 1 = last block for the scan, don't ask driver for more! */
  uint8_t *buf; /* ptr to device internal dma buffer */
  YR_MEMORY_BLOCK block;
};

static const uint8_t *getblkaddr(YR_MEMORY_BLOCK *self);
static YR_MEMORY_BLOCK *getblk(YR_MEMORY_BLOCK_ITERATOR *self);

/* -------------------------------------------------------------------------- */
/* state -------------------------------------------------------------------- */

static YR_COMPILER *compiler;
static YR_RULES *rules;
static YR_SCANNER *scanner;
static struct machyara_scan *scan;

static struct iterator_context iterctx = {
  .block = {
    .context = &iterctx,
    .fetch_data = getblkaddr,
  }
};

/* TODO */
/* implement firstblk and nextblk, yara can iterate from start to end multiple
 * times! */

static YR_MEMORY_BLOCK_ITERATOR iterator = {
  .context = &iterctx,
  .first = getblk,
  .next = getblk,
  /* .file_size ? */
};

/* TODO */
/* test stuff, remove later */

const char *dummy_rule =
" rule dummy { "
"   strings: "
"     $str = \"dummy\" "
"   condition: "
"     $str "
" } ";

const char buf1[] = "sapatopatopato";
const char buf2[] = "stuffdummybuf";

static const uint8_t *dma;
static size_t dmasz;
static size_t dmaoff;

/* -------------------------------------------------------------------------- */
/* logic -------------------------------------------------------------------- */

/* ask the driver for a block, copy to device's internal buffer via dma, update
 * iterator context accordingly */
static uint8_t update_blk(struct iterator_context *ctx) {
  static int i=1;

  dbg("update_blk(%d)\n", i++);

  /* TODO */
  /* currently this is emulated behavior, just for testing */

  static uint8_t internal_buf[1];

  /* on the device, we need to pick the smallest between the userbuf size and
   * the internal_buf size.
   *
   * if you are motivated, you can allow userbuf to be bigger than
   * internal_buf, but you'll need to implement a buffered dma read from it. */

  if (dmaoff >= dmasz) {
    ctx->valid = 0;
    ctx->last = 1;
    return ctx->valid;
  }

  ctx->block.base = dmaoff;

  if (dmasz - dmaoff < sizeof internal_buf) {
    ctx->block.size = dmasz - dmaoff;
    ctx->last = 1;
  }

  else {
    ctx->block.size = sizeof internal_buf;
    ctx->last = 0;
  }

  memcpy(internal_buf, dma + dmaoff, ctx->block.size);
  dmaoff += ctx->block.size;

  ctx->valid = 1;
  ctx->buf = internal_buf;

  return ctx->valid;
}

/* yara calls this function once to get the memory block's first address */
static const uint8_t *getblkaddr(YR_MEMORY_BLOCK *self) {
  struct iterator_context *ctx = self->context;
  return ctx->buf;
}

static YR_MEMORY_BLOCK *getblk(YR_MEMORY_BLOCK_ITERATOR *self) {
  struct iterator_context *ctx = self->context;

  /* this sucks */

  if (ctx->valid) {
    ctx->valid = 0;
    return &ctx->block;
  }

  if (!ctx->last) {
      if (update_blk(ctx)) {
      ctx->valid = 0;
      return &ctx->block;
    }

    return NULL;
  }

  return NULL;
}

static int callback(YR_SCAN_CONTEXT *context, int message, void *message_data,
                    void *user_data) {
  const char *identifier = NULL;
  uint8_t matched = 0;

  switch (message) {
  case CALLBACK_MSG_RULE_MATCHING:
    matched = 1;
    /* fall through */

  case CALLBACK_MSG_RULE_NOT_MATCHING:
    identifier = ((YR_RULE *)message_data)->identifier;
    break;

  case CALLBACK_MSG_SCAN_FINISHED:
    puts("scan finished");
    break;

  case CALLBACK_MSG_CONSOLE_LOG:
    printf("console log: %s\n", (char *)message_data);
    break;
  }

  if (identifier) {
    machyara_scan_add_rule(scan, identifier, matched);
    printf("rule=%s -> matched=%u\n", identifier, matched);
  }

  return CALLBACK_CONTINUE;
}

/* -------------------------------------------------------------------------- */
/* initialization & deinitialization ---------------------------------------- */

/* TODO */
/* this is a mess... */

static void init(void) {
  int err;

  check (yr_initialize())

  check (yr_compiler_create(&compiler))
  check (yr_compiler_add_string(compiler, dummy_rule, NULL))
  check (yr_compiler_get_rules(compiler, &rules))

  check (yr_scanner_create(rules, &scanner))
  yr_scanner_set_callback(scanner, callback, NULL);

  check ((scan = machyara_scan_create()) ? 0 : -ENOMEM)
}

static void deinit(void) {
  machyara_scan_destroy(scan);
  yr_scanner_destroy(scanner);
  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);
  yr_finalize();
}

/* -------------------------------------------------------------------------- */
/* example workflow --------------------------------------------------------- */

static void test(void) {
  int err;

  puts("buf2");
  dma = buf2;
  dmasz = strlen(buf2);
  dbg("dmasz=%zu\n", dmasz);
  check (yr_scanner_scan_mem_blocks(scanner, &iterator));
  /* TODO */
}

/* -------------------------------------------------------------------------- */
/* initialization/deinitialization ------------------------------------------ */

int main() {
  init();
  test();
  deinit();

  return EXIT_SUCCESS;
}

/* -------------------------------------------------------------------------- */
