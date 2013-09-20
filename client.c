#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kaji.h"
#include "util.h"
#include "client.h"

/* To supress config.h error for libbfd
   Will be replaced when autotools are used */
#define PACKAGE "Kaji"
#define PACKAGE_VERSION "0.0.1"

#include <bfd.h>
#include <dis-asm.h>
#include <distorm.h>

void usage(char *progname)
{
    fprintf(stderr, "Usage: %s BINARY PID SYMBOL | SYMBOL+OFFSET\n", progname);
}

/* Parse options */
int parse_opts(struct env_opts *env, char *argv[])
{
    int ret = 0;
    char *buff;
    char *name;
    char *off;
    char *plus = "+";
    
    /* Set path*/
    env->path = argv[1];

    /* Set symbol+offset*/
    buff  = strdup(argv[3]);
    if (strchr(buff, '+')){
        name = strsep(&buff, plus);
        off = buff;
        env->sym = name;
        env->offset = strtol(off, NULL, 0);
    }
    else{
        env->sym = buff;
        env->offset = 0;
    }

    /* Set PID*/
    env->pid = (pid_t) strtol(argv[2], NULL, 0);

    return ret;

}

/* Resolve symbol name to addr */
long get_sym_addr(char* path, char* sym)
{
    long addr = 0;

    /* load symbol table*/
    long size;
    long nsym;
    asymbol **asymtab;
 
    bfd_init();
    bfd *abfd = bfd_openr(path, NULL);
 
    bfd_check_format(abfd, bfd_object);
    size = bfd_get_symtab_upper_bound(abfd);
    asymtab = malloc(size);
    nsym = bfd_canonicalize_symtab(abfd, asymtab); /*reads symtab*/

    /* get symbol addr*/
    long i = 0;
    int found = 0;
    const char* asymbol_name;

    while (i < nsym)
    {
        asymbol_name = bfd_asymbol_name(asymtab[i]);
        if (!strcmp(sym, asymbol_name)){
            addr = bfd_asymbol_value(asymtab[i]);
            found = 1;
            return addr;
        }
        else if (!found){
            i++;
        }
    }

    if (!found){
        printf("Symbol Not found! \n");
        exit(-1);   
    }
    return -1;
}


/* Get instruction size */
size_t get_insn_size(char* path, long addr)
{
    _DecodeResult res;
    _DecodedInst decodedInstructions[1];
    unsigned int decodedInstructionsCount = 0;
    _DecodeType dt = Decode64Bits;  // default is 64 bits
    _OffsetType offset = 0;

    FILE* f;
    unsigned long filesize = 0, bytesread = 0;
    struct stat st;

    unsigned char *buf;

    f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        exit(-1);
    }

    if (fstat(fileno(f), &st) != 0) {
        perror("fstat");
        fclose(f);
        exit(-1);
    }
    filesize = st.st_size;

    buf = malloc(filesize);
    if (buf == NULL) {
        perror("File too large.");
        fclose(f);
        exit(-1);
    }

    // offset calculation from addr
    unsigned long mask = 0x000fff;
    offset = addr & mask;

    // adjust offset, the way we need it
    fseek(f, offset, SEEK_SET);
    filesize -= offset;

    // read file into memory
    bytesread = fread(buf, 1, filesize, f);

    if (bytesread != filesize) {
        perror("Can't read file into memory.");
        free(buf);
        fclose(f);
        exit(-1);
    }

    fclose(f);

    // start disassembly
    res = distorm_decode(offset, (const unsigned char*)buf, 20, dt, decodedInstructions, 1, &decodedInstructionsCount);
    if (res == DECRES_INPUTERR) {
        // Null buffer? Decode type not 16/32/64?
        fputs("Input error, halting!\n", stderr);
        free(buf);
        exit(-1);
    }

    free(buf);
    return decodedInstructions[0].size;

}

int main(int argc, char *argv[])
{
    int sock_fd, ret, stat, reply;
    struct sockaddr_un addr;
    const char pathname[] = "/tmp/kaji.sock";
    struct kaji_command command;
    struct env_opts env;

    if (argc != 4) {
        usage(argv[0]);
        exit(-1);
    }

    ret = parse_opts(&env, argv);

#if 0
    printf("Name : %s\n", env.path);
    printf("PID : %d\n", env.pid);
    printf("Symbol : %s\n", env.sym);
    printf("Offset : %lx\n", env.offset);
#endif

    /*
     * Use ptrace to attach the instrumented process,
     * the in-process-agent thread is untouched.
     */
    ret = ptrace(PTRACE_ATTACH, env.pid, NULL, NULL);
    _assert(ret != -1, "PTRACE_ATTACH");
    ret = waitpid(env.pid, &stat, WUNTRACED);
    _assert((ret == env.pid) && WIFSTOPPED(stat), "waitpid");

    /* Connect to in-process-agent */
    sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    _assert(socket >= 0, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), pathname);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
    ret = connect(sock_fd, (struct sockaddr*) &addr, sizeof(addr));
    _assert(ret != -1, "connect");

    /* Construct and send command to IPA */
    command.addr = (void*) (get_sym_addr(env.path, env.sym) +env.offset);
    command.len = get_insn_size(env.path, (long) command.addr);
    if (command.len < 5){
        fprintf(stderr, "I can't instrument instructions < 5 bytes for now :(\n");
        exit(-1);
    }
//    command.addr = (void*) strtol(argv[3], NULL, 0);
//    command.len = (size_t) strtol(argv[4], NULL, 0);
    ret = send(sock_fd, &command, sizeof(command), 0);
    _assert(ret == sizeof(struct kaji_command), "send");

    /* Verify reply form IPA */
    ret = recv(sock_fd, &reply, sizeof(reply), 0);
    _assert(ret == sizeof(reply) && reply == KAJI_REPLY_OK, "recv");

    /* Detach the instrumented process */
    ret = ptrace(PTRACE_DETACH, env.pid, NULL, 0);
    _assert(ret != -1, "PTRACE_DETACH");

    return 0;
}

