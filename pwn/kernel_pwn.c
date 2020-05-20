/*
 * main.c
 *
 */
// gcc exp.c -o exp --static -lpthread
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <linux/prctl.h>
#include <stdint.h>


#define MALLOC 0x271A
#define FREE   0x2766
#define EDIT1  0x1A0A
#define EDIT2  0x22B8 
pid_t pid;


void debug(){
    getchar();
}

int main(int argc, char *argv[]){
    int fd = open("/dev/tshop",0);
    debug();
    ioctl(fd,MALLOC,0);
    fork()；
}
