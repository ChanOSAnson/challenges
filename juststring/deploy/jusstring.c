#include <stdio.h>
#include <unistd.h>

int hello() {
    char name[400];
    printf("Enter your name:\n");
    gets(name);
    printf("Hello: %s\n", name);
    return 0;
}

void flag()
{
    printf("Here's your flag : CZ4067{h3ll0_w0rld_s33ms_t0ugh}");
    return;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    hello();
    return 0;
}
