#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

#include <jni.h>

#include "util.h"
#include "hook.h"

JNIEXPORT void JNICALL
Java_com_example_jxwang_testinject_MainActivity_pingInject(JNIEnv *env, jobject instance) {
    // TODO
    HOOKLOG("Ping is %s", "OK");
}

void inline hook_cacheflush(unsigned int begin, unsigned int end)
{
    const int syscall = 0xf0002;
    __asm __volatile (
    "mov	 r0, %0\n"
            "mov	 r1, %1\n"
            "mov	 r7, %2\n"
            "mov     r2, #0x0\n"
            "svc     0x00000000\n"
    :
    :	"r" (begin), "r" (end), "r" (syscall)
    :	"r0", "r1", "r7"
    );
}

int hook(struct hook_t *h, int pid, char *libname, char *funcname, void *hook_arm, void *hook_thumb)
{
    unsigned long int addr;
    int i;

    if (find_name(pid, funcname, libname, &addr) < 0) {
        HOOKLOG("can't find: %s\n", funcname);
        return 0;
    }

    HOOKLOG("hooking:   %s = 0x%lx ", funcname, addr);
    strncpy(h->name, funcname, sizeof(h->name)-1);

    if (addr % 4 == 0) {
        HOOKLOG("ARM using 0x%lx\n", (unsigned long)hook_arm);
        h->thumb = 0;
        h->patch = (unsigned int)hook_arm;
        h->orig = addr;
        h->jump[0] = 0xe59ff000; // LDR pc, [pc, #0]
        h->jump[1] = h->patch;
        h->jump[2] = h->patch;
        for (i = 0; i < 3; i++)
            h->store[i] = ((int*)h->orig)[i];
        for (i = 0; i < 3; i++)
            ((int*)h->orig)[i] = h->jump[i];
    }
    else {
        if ((unsigned long int)hook_thumb % 4 == 0)
            HOOKLOG("warning hook is not thumb 0x%lx\n", (unsigned long)hook_thumb);
        h->thumb = 1;
        HOOKLOG("THUMB using 0x%lx\n", (unsigned long)hook_thumb);
        h->patch = (unsigned int)hook_thumb;
        h->orig = addr;
        h->jumpt[1] = 0xb4;
        h->jumpt[0] = 0x60; // push {r5,r6}
        h->jumpt[3] = 0xa5;
        h->jumpt[2] = 0x03; // add r5, pc, #12
        h->jumpt[5] = 0x68;
        h->jumpt[4] = 0x2d; // ldr r5, [r5]
        h->jumpt[7] = 0xb0;
        h->jumpt[6] = 0x02; // add sp,sp,#8
        h->jumpt[9] = 0xb4;
        h->jumpt[8] = 0x20; // push {r5}
        h->jumpt[11] = 0xb0;
        h->jumpt[10] = 0x81; // sub sp,sp,#4
        h->jumpt[13] = 0xbd;
        h->jumpt[12] = 0x20; // pop {r5, pc}
        h->jumpt[15] = 0x46;
        h->jumpt[14] = 0xaf; // mov pc, r5 ; just to pad to 4 byte boundary
        memcpy(&h->jumpt[16], (unsigned char*)&h->patch, sizeof(unsigned int));
        unsigned int orig = addr - 1; // sub 1 to get real address
        for (i = 0; i < 20; i++) {
            h->storet[i] = ((unsigned char*)orig)[i];
            //HOOKLOG("%0.2x ", h->storet[i])
        }
        //HOOKLOG("\n")
        for (i = 0; i < 20; i++) {
            ((unsigned char*)orig)[i] = h->jumpt[i];
            //HOOKLOG("%0.2x ", ((unsigned char*)orig)[i])
        }
    }
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
    return 1;
}

void hook_precall(struct hook_t *h)
{
    int i;

    if (h->thumb) {
        unsigned int orig = h->orig - 1;
        for (i = 0; i < 20; i++) {
            ((unsigned char*)orig)[i] = h->storet[i];
        }
    }
    else {
        for (i = 0; i < 3; i++)
            ((int*)h->orig)[i] = h->store[i];
    }
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

void hook_postcall(struct hook_t *h)
{
    int i;

    if (h->thumb) {
        unsigned int orig = h->orig - 1;
        for (i = 0; i < 20; i++)
            ((unsigned char*)orig)[i] = h->jumpt[i];
    }
    else {
        for (i = 0; i < 3; i++)
            ((int*)h->orig)[i] = h->jump[i];
    }
    hook_cacheflush((unsigned int)h->orig, (unsigned int)h->orig+sizeof(h->jumpt));
}

void unhook(struct hook_t *h)
{
    HOOKLOG("unhooking %s = %x  hook = %x ", h->name, h->orig, h->patch);
    hook_precall(h);
}

static struct hook_t sleep_h;

unsigned int my_sleep(unsigned int seconds){
    int (*orig_sleep)(unsigned int);
    orig_sleep = (void*)sleep_h.orig;

    hook_precall(&sleep_h);
    int res = orig_sleep(seconds);
    hook_postcall(&sleep_h);
    HOOKLOG("sleep() called", 0);

    return res;
}

unsigned int my_sleep_arm(unsigned int seconds){
    return my_sleep(seconds);
}

static struct hook_t open_h;

int my_open(const char *pathname, int flags, ...){
    int (*orig_open)(const char *, int , ...);
    orig_open = (void*)open_h.orig;

    hook_precall(&open_h);

    va_list  args;
    va_start(args, flags);
    mode_t mode = (mode_t) va_arg(args, int);
    va_end(args);
    int res = orig_open(pathname, flags, mode);

    hook_postcall(&open_h);
    HOOKLOG("open() called: pathname=%s", pathname);

    return res;
}

int my_open_arm(const char *pathname, int flags, ...){
    va_list  args;
    va_start(args, flags);
    mode_t mode = (mode_t) va_arg(args, int);
    va_end(args);
    return my_open(pathname, flags, mode);
}

void __attribute__ ((constructor)) libhook_main(){
    pid_t pid = getpid();

    HOOKLOG("LIBRARY LOADED FROM PID %d.", pid);
    hook(&sleep_h, pid, "libc.", "sleep", my_sleep_arm, my_sleep);
    int i=0;
    while (i++ < 5){
        HOOKLOG("sleep count : %d", i);
        sleep(1);
    }
    unhook(&sleep_h);

    hook(&open_h, pid, "libc.", "open", my_open_arm, my_open);
}
