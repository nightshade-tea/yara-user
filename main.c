#include <stdio.h>
#include <stdlib.h>
#include <yara.h>
#include "scan.h"

const char *dummy_rule =
" rule dummy { "
"   strings: "
"     $str = \"dummy\" "
"   condition: "
"     $str "
" } ";

const char buf1[] = "sapatopatopato";
const char buf2[] = "stuffdummybuf";

static int callback(YR_SCAN_CONTEXT *context, int message, void *message_data,
                    void *user_data) {
  switch (message) {
  case CALLBACK_MSG_RULE_MATCHING:
    printf("rule=%s -> match\n", ((YR_RULE *)message_data)->identifier);
    break;

  case CALLBACK_MSG_RULE_NOT_MATCHING:
    printf("rule=%s -> no match\n", ((YR_RULE *)message_data)->identifier);
    break;

  case CALLBACK_MSG_SCAN_FINISHED:
    puts("scan finished");
    break;

  case CALLBACK_MSG_CONSOLE_LOG:
    printf("console log: %s\n", (char *)message_data);
    break;
  }

  return CALLBACK_CONTINUE;
}

int main() {
  YR_COMPILER *compiler;
  YR_RULES *rules;
  int err;

  if ((err = yr_initialize())) {
    fprintf(stderr, "yr_initialize(): err=%d", err);
    return EXIT_FAILURE;
  }
  if ((err = yr_compiler_create(&compiler))) {
    fprintf(stderr, "yr_compiler_create(): err=%d", err);
    return EXIT_FAILURE;
  }

  if ((err = yr_compiler_add_string(compiler, dummy_rule, NULL))) {
    fprintf(stderr, "yr_compiler_add_string(): err=%d", err);
    return EXIT_FAILURE;
  }
  if ((err = yr_compiler_get_rules(compiler, &rules))) {
    fprintf(stderr, "yr_compiler_get_rules(): err=%d", err);
    return EXIT_FAILURE;
  }

  puts("buf1");
  if ((err = yr_rules_scan_mem(rules, buf1, sizeof buf1, 0, callback, 0, 0))) {
    fprintf(stderr, "yr_rules_scan_mem(): err=%d", err);
    return EXIT_FAILURE;
  }

  puts("buf2");
  if ((err = yr_rules_scan_mem(rules, buf2, sizeof buf2, 0, callback, 0, 0))) {
    fprintf(stderr, "yr_rules_scan_mem(): err=%d", err);
    return EXIT_FAILURE;
  }

  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);
  yr_finalize();

  return EXIT_SUCCESS;
}
