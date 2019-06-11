#ifndef _UTILS
#define _UTILS

#include <stdio.h>
#include <windows.h>
#include <assert.h>


#define LOG_FILE "log.txt"


void flog(char *text,...);
void get_error_msg(char *out);

#endif