#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <yara.h>

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

int main ()
{
  int err;

  chk (yr_initialize ());
  chk (yr_finalize ());

  return EXIT_SUCCESS;
}
