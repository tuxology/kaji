#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#include "server.h"
#include "kaji.h"
#include "error.h"

/* Define tracepoint event */
#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_kaji_test.h"

#define MAX_LISTEN 16
#define MAX_EPOLL_EVENTS 64

#define min(a, b) ( (a) > (b) ? (a) : (b) )

/* Assembly labels declared as functions here to enable relocation. */
extern void kaji_trampoline();
extern void __kaji_trampoline_placeholder();
extern void __kaji_trampoline_end();
extern void __kaji_trampoline_call();

#define PAGESIZE 4096

/* Set a section of memory to be writable */
static int set_writable(void* addr, size_t len)
{
    ptrdiff_t mask = ~0xfffUL;

    return mprotect((void *) ((ptrdiff_t) addr & mask),
            (len + PAGESIZE - 1) & mask,
            PROT_READ|PROT_WRITE|PROT_EXEC);
}

/* Set a given fd to nonblocking */
static int set_nonblocking(int fd)
{
    int flags, ret;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        PERROR("fcntl GETFL failed");
        goto error;
    }

    flags |= O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);
    if (ret == -1) {
        ERR("fcntl SETFL failed");
        goto error;
    }

    return 0;

error:
    return -1;
}


void __attribute__ ((constructor)) kaji_init(void)
{
    pthread_t loop_thread;
    pthread_create(&loop_thread, NULL, kaji_loop, NULL);
}

void __attribute__ ((destructor)) kaji_fini(void)
{
    /* TODO */
}

/* Main in-process-agent event loop */
void* kaji_loop(void *arg)
{
    int sock_fd, ret, efd;
    struct sockaddr_un addr;
    const char pathname[] = "/tmp/kaji.sock";
    struct epoll_event ev;
    struct epoll_event *events;

    /* Setup unix domain socket and listen */
    if ((sock_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        PERROR("Create socket failed");
        goto error;
    }

    if (set_nonblocking(sock_fd)) {
        ERR("Set fd %d to nonblocking failed", sock_fd);
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), pathname);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
    (void) unlink(pathname);

    ret = bind(sock_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    if (ret) {
        PERROR("Bind socket failed");
        goto error;
    }

    if (listen(sock_fd, MAX_LISTEN) != 0) {
        PERROR("Listen socket failed");
        goto error;
    }

    /* Setup epoll event loop */
    if ((efd = epoll_create1(0)) == -1) {
        PERROR("Epoll_create1 failed");
        goto error;
    }

    memset(&ev, 0, sizeof(ev));
    ev.data.fd = sock_fd;
    ev.events = EPOLLIN;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, sock_fd, &ev) == -1) {
        PERROR("EPOLL_CTL_ADD failed");
        goto error;
    }

    events = calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));

    /* Event loop starts here */
    for(;;) {
        int nr_events, i;

        nr_events = epoll_wait(efd, events, MAX_EPOLL_EVENTS, -1);
        for (i = 0; i < nr_events; i++) {
            if (events[i].data.fd == sock_fd) {
                /* We have a new client, accept it and add to epoll queue*/
                int conn_fd;

                conn_fd = accept(sock_fd, NULL, 0), ret;
                set_nonblocking(conn_fd);

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = conn_fd;
                if (epoll_ctl(efd, EPOLL_CTL_ADD, conn_fd, &ev) == -1) {
                    PERROR("EPOLL_CTL_ADD failed");
                    goto error;
                }
            } else {
                /* We've got a new command, handle it */
                ssize_t count;
                char buffer[4096];
                struct kaji_command command;
                int reply;

                /* TODO: handle possible partial message */
                count = read(events[i].data.fd, buffer, sizeof(buffer));
                if (count > 0) {
                    if (count != sizeof(struct kaji_command)) {
                        ERR("Read command failed");
                        goto error;
                    }

                    memcpy(&command, buffer, sizeof(struct kaji_command));
                    kaji_install_trampoline(command.addr, command.len);

                    reply = KAJI_REPLY_OK;
                    write(events[i].data.fd, &reply, sizeof(reply));
                }
            }
        }
    }

error:
    // TODO: Fix memory/fd leak here
    free(events);
    close(efd);
    close(sock_fd);

    return NULL;
}

/* Install trampoline to instrumented process */
void kaji_install_trampoline(void* addr, size_t len)
{
    unsigned char jmp_buff[] = { 0xe9, 0, 0, 0 , 0 };
    int32_t jmp_offset;
    void *jmp_pad, *placeholder, *probe_addr = (void*) kaji_probe;
    size_t trampoline_size = __kaji_trampoline_end - kaji_trampoline;

    /* Set memory permission to writable */
    if (set_writable(addr, len) == -1) {
        ERR("set %p to writable failed", addr);
        goto error;
    }
    if (set_writable(kaji_trampoline, trampoline_size) == -1) {
        ERR("set %p to writable failed", kaji_trampoline);
        goto error;
    }

    /* Rewrite address of probe in trampoline */
    memcpy(__kaji_trampoline_call + 2, &probe_addr, sizeof(probe_addr));

    /* We need to place the jmp pad at lower memory to fit in a jmp instruction */
    jmp_pad = mmap((void*) 0x100000,                    /* address */
               trampoline_size, /* length */
               PROT_READ | PROT_WRITE | PROT_EXEC,      /* permission */
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, /* flags */
               -1,                                      /* fd */
               0                                        /* offset */);
    if (jmp_pad == MAP_FAILED) {
        ERR("mmap memory for jmp_pad failed");
        goto error;
    }
    memcpy(jmp_pad, kaji_trampoline, __kaji_trampoline_end - kaji_trampoline);
    placeholder = jmp_pad + (__kaji_trampoline_placeholder - kaji_trampoline);

    /* Copy the origin instruction to trampoline */
    memcpy(placeholder, addr, len);

    /* Write a jmp from trampoline back to origin code flow */
    jmp_offset = addr - (void*) (placeholder + len);
    memcpy(jmp_buff + 1, &jmp_offset, sizeof(jmp_offset));
    memcpy(placeholder + len, jmp_buff, sizeof(jmp_buff));

    /* Write a jmp to trampoline */
    jmp_offset = (void*) jmp_pad - (addr + len);
    memcpy(jmp_buff + 1, &jmp_offset, sizeof(jmp_offset));
    memcpy(addr, jmp_buff, sizeof(jmp_buff));

error:
    return;
}

/* This is the instrumented probe */
void kaji_probe()
{
    tracepoint(ust_kaji_test, tptest);
}
