#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_it(const char *src) {
    char buf[16];
    strcpy(buf, src);            /* flawfinder/cppcheck: buffer overflow */
    printf(buf);                 /* format string vulnerability */
}

int main(int argc, char **argv) {
    if (argc > 1) copy_it(argv[1]);
    char *p = malloc(10);
    free(p);
    free(p);                     /* double free */
    return 0;
}
