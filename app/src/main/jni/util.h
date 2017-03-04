//
// Created by JX Wang on 2016/4/1.
//

#ifndef TESTINJECT_UTIL_H
#define TESTINJECT_UTIL_H

#include <termios.h>

int find_name(pid_t pid, char *name, char *libn, unsigned long *addr);
int find_libbase(pid_t pid, char *libn, unsigned long *addr);

#endif //TESTINJECT_UTIL_H
