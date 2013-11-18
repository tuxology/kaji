#include <stdio.h>
#include <unistd.h>
#include <signal.h>

volatile int v=43;

void do_stuff()
{
    int i;
    for (i = 0; i < 10; ++i)
        printf("I am in do_stuff().\n");
}

int main()
{
    signal(SIGUSR1, do_stuff);
    pause();
    return 0;
}
