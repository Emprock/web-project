//
// Created by JX Wang on 2016/4/1.
//

#ifndef TESTINJECT_HOOK_H
#define TESTINJECT_HOOK_H

#include <android/log.h>
#include <unistd.h>

#define HOOKLOG(F,...) \
    __android_log_print( ANDROID_LOG_INFO, "LIBHOOK", F, __VA_ARGS__ )

struct hook_t {
    unsigned int jump[3];
    unsigned int store[3];
    unsigned char jumpt[20];
    unsigned char storet[20];
    unsigned int orig;
    unsigned int patch;
    unsigned char thumb;
    unsigned char name[128];
    void *data;
};

int start_coms(int *coms, char *ptsn);

void hook_cacheflush(unsigned int begin, unsigned int end);
void hook_precall(struct hook_t *h);
void hook_postcall(struct hook_t *h);
int hook(struct hook_t *h, int pid, char *libname, char *funcname, void *hook_arm, void *hook_thumb);
void unhook(struct hook_t *h);

#endif //TESTINJECT_HOOK_H
