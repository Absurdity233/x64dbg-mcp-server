// Raises a handled access violation so the debugger sees a real first-chance
// exception. Used to check what the plugin actually records.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(){
  const char* rp = getenv("ADTEST_REPORT");
  FILE* o = rp ? fopen(rp,"w") : stdout; if(!o) o=stdout;
  __try { *(volatile int*)0 = 1; }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    fprintf(o, "caught 0x%08X\n", (unsigned)GetExceptionCode());
    fflush(o);
  }
  int r; DWORD n;
  ReadFile(INVALID_HANDLE_VALUE, &r, 4, &n, NULL);
  fprintf(o, "ReadFile bad handle -> %lu\n", GetLastError());
  fflush(o);
  if(rp) fclose(o);
  return 0;
}
