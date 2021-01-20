/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#define MULTITHREADING
// #define SINGLETHREAD

#ifdef MULTITHREADING
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#endif

#if defined(MULTITHREADING) || defined(SINGLETHREAD)
static int sub_fun_call_num1 = 0;
static int sub_fun_call_num2 = 0;
void t1_sub_fun() {
    sub_fun_call_num1 ++;
    return;     
}

void t2_sub_fun() {
    sub_fun_call_num2 ++;
    return;
}

void t1_fun() {
    for(int i = 0; i < 2222; i++){
        t1_sub_fun();
    }
}

void t2_fun() {
    for(int i = 0; i < 1111; i++){
        t2_sub_fun();
    }
}
#endif

#ifdef MULTITHREADING
void *thread_1(void *arg)
{
    t1_fun();
    return NULL;
}

void *thread_2(void *arg)
{
    t2_fun();
    return NULL;
}
#endif

void test_fun() {
    int i = 0;
    i ++;
    return;
}


int main(){

#ifdef MULTITHREADING
    int pt1, pt2;
    pthread_t thread[2];
    pt1 = pthread_create(&thread[0], NULL, thread_1, NULL);
    pt2 = pthread_create(&thread[1], NULL, thread_2, NULL);

    if (pt1)
    {
        printf("ERROR; return code is %d\n", pt1);
        // printf("ERROR; return code is %d, %d, %d, %d\n\n", pt1, pt2, pt3, pt4);
        return EXIT_FAILURE;
    }
    if (pt2)
    {
        printf("ERROR; return code is %d\n", pt1);
        // printf("ERROR; return code is %d, %d, %d, %d\n\n", pt1, pt2, pt3, pt4);
        return EXIT_FAILURE;
    }
    for(int i = 0; i < 2; i++)
    {
        pthread_join(thread[i], NULL);
    }
    printf("sub_fun_call_num %d\n", sub_fun_call_num1 + sub_fun_call_num2);
    return EXIT_SUCCESS;
#elif defined(SINGLETHREAD)
    t1_fun();
    t2_fun();
#else
    test_fun();
    return 0;
#endif   
}