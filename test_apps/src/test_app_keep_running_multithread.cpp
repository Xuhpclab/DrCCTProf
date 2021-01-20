/*
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <unistd.h>
#include <sys/syscall.h>
#include <iostream>
using namespace std;
static int sub_fun_call_num_a = 0;
static int sub_fun_call_num_b = 0;
static int sub_sub_fun_call_num = 0;

void
SubSubFunction()
{
    sub_sub_fun_call_num++;
}

void
SubFunctionB()
{
    sub_fun_call_num_b++;
    SubSubFunction();
}

void
SubFunctionA()
{
    sub_fun_call_num_a++;
    SubFunctionB();
}

void
Function()
{
    int j = 1;
    while (j > 0 && j < 11) {
        if (j % 2 == 1) {
            SubFunctionA();
        } else {
            SubFunctionB();
        }
        j++;
    }
}

void MainThread()
{
    #ifdef SYS_gettid
    pid_t tid = syscall(SYS_gettid);
    cout << "thread1 id is " << tid << endl;
    #else
    #error "SYS_gettid unavailable on this system"
    #endif
    int i = 0;
    while (i < 150) {
        i++;
        Function();
        sleep(1);
    }
    cout << "MainThread i======= " << i << endl;
}

static int sub_fun_call_num_a2 = 0;
static int sub_fun_call_num_b2 = 0;
static int sub_sub_fun_call_num2 = 0;

void
SubSubFunction2()
{
    sub_sub_fun_call_num2++;
}

void
SubFunctionB2()
{
    sub_fun_call_num_b2++;
    SubSubFunction2();
}

void
SubFunctionA2()
{
    sub_fun_call_num_a2++;
    SubFunctionB2();
}

void
Function2()
{
    int j = 1;
    while (j > 0 && j < 11) {
        if (j % 2 == 1) {
            SubFunctionA2();
        } else {
            SubFunctionB2();
        }
        j++;
    }
}

void *thread_2(void *arg)
{
    #ifdef SYS_gettid
    pid_t tid = syscall(SYS_gettid);
    cout << "thread2 id is " << tid << endl;
    #else
    #error "SYS_gettid unavailable on this system"
    #endif
    
    int i = 0;
    while (i < 100) {
        i++;
        Function2();
        sleep(1);
    }
    cout << "thread_2 i======= " << i << endl;
    return NULL;
}

int
main()
{
    cout << "process is " << getpid() << endl;
    // int pt1, pt2;
    pthread_t thread[1];
    // pt1 = pthread_create(&thread[0], NULL, thread_1, NULL);
    int pt1 = pthread_create(&thread[0], NULL, thread_2, NULL);
    if (pt1)
    {
        printf("ERROR; return code is %d\n", pt1);
        return EXIT_FAILURE;
    }
    MainThread();
    for(int i = 0; i < 1; i++)
    {
        pthread_join(thread[i], NULL);
    }
    
    return 0;
}