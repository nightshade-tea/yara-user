#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <yara.h>

const char *dummy_rule = "\
rule dummy { \
  condition: \
    \"dummy\"\
}\
";

const char buf1[] = "sapatopatopato";
const char buf2[] = "dummybuf";

/* -------------------------------------------------------------------------- */

#define pe(err) \
  error ("(%s:%d) %s() failed: %d\n", __FILE__, __LINE__, __func__, err)

#define nzpe(err) \
  if (err) pe (err)

#define chk(expr) \
  nzpe ((expr))

static __attribute__ ((noreturn)) void
error (const char *restrict format, ...)
{
  va_list args;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  exit (EXIT_FAILURE);
}

/* -------------------------------------------------------------------------- */

static int
callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  printf ("message=%d\n", message);

  return CALLBACK_CONTINUE;
}

int main ()
{
  YR_COMPILER *compiler;
  YR_RULES *rules;
  int err;

  chk (yr_initialize ());
  chk (yr_compiler_create (&compiler));

  chk (yr_compiler_add_string (compiler, dummy_rule, NULL));
  chk (yr_compiler_get_rules (compiler, &rules));

  puts ("buf2");
  chk (yr_rules_scan_mem (rules, buf2, sizeof buf2, 0, callback, 0, 0));
  puts ("buf1");
  chk (yr_rules_scan_mem (rules, buf1, sizeof buf1, 0, callback, 0, 0));

  yr_rules_destroy (rules);
  yr_compiler_destroy (compiler);
  yr_finalize ();

  return EXIT_SUCCESS;
}
