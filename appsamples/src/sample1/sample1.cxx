#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <vector>
#include <pthread.h>
using namespace std;



void t1_sub_fun() {
    printf("t1_sub_fun\n");
}

void t1_fun1() {
    t1_sub_fun();
}

void t1_fun2() {
    t1_sub_fun();
}

void *thread_1(void *arg)
{
    t1_fun1();
    t1_fun2();
}

void exception_fun() {
    throw 10;
}

void t2_subfun1() {
    exception_fun();
}

void t2_subfun2() {
    printf("t2_subfun2\n");
}

void t2_fun1(){
    try {
        t2_subfun1();
    } catch (int e) {
        printf("t2_fun1 cache throw %d\n", e);
    }
    t2_subfun2();
}

void t2_fun2() {
    t2_subfun2();
}

void *thread_2(void *arg)
{
    t2_fun1();
    t2_fun2();
}
static int sub_thread_deep = 0;
pthread_mutex_t t3_sub_mutex;
extern void *t3_sub_thread(void *arg);
void *t3_sub_thread(void *arg)
{
    printf("new t3_sub_thread \n");
    int cur_deep = sub_thread_deep;
    pthread_mutex_lock(&t3_sub_mutex);
    if(sub_thread_deep < 10) {
        sub_thread_deep ++;
        pthread_mutex_unlock(&t3_sub_mutex);
        pthread_t sub_pd;
        int pt = pthread_create(&sub_pd, NULL, t3_sub_thread, NULL);
        pthread_join(sub_pd, NULL);
    }
    else
    {
        pthread_mutex_unlock(&t3_sub_mutex);
    }
    
}

void *thread_3(void *arg)
{
    printf("new thread_3 \n");
    pthread_mutex_init(&t3_sub_mutex, NULL);
    pthread_t sub_pd;
    int pt = pthread_create(&sub_pd, NULL, t3_sub_thread, NULL);
    pthread_join(sub_pd, NULL);
    pthread_mutex_destroy(&t3_sub_mutex);
}

int* t4_memory_create()
{
    return (int*)malloc(100*sizeof(int)); 
}

void t4_memory_free(int* array)
{
    free((void*)array);
}

int global_int = 1024;
void *thread_4(void *arg)
{
    int** int_tensor = (int**)malloc(100*sizeof(int*));
    for(int i = 0; i < 100; i++){
        int_tensor[i] = t4_memory_create();
    }
    for (int i = 0; i < 100; i++) {
        for(int j = 0; j < 100; j++){
            int_tensor[i][j] = global_int;
            printf("thread_4 init int_tensor[%d][%d]\n", i, j);
        }
    }
    for(int i = 0; i < 100; i++){
        t4_memory_free(int_tensor[i]);
    }
    free((void*)int_tensor);
}
#define THREAD_NUM 1
int main(){
    int pt1, pt2, pt4;
    // int pt3;
    pthread_t thread[THREAD_NUM];
    pt1 = pthread_create(&thread[0], NULL, thread_1, NULL);
    pt2 = pthread_create(&thread[1], NULL, thread_2, NULL);
    // pt3 = pthread_create(&thread[0], NULL, thread_3, NULL);
    pt4 = pthread_create(&thread[2], NULL, thread_4, NULL);
    // if (pt3)
    // if (pt1&&pt2&&pt3&&pt4)
    // {
    //     printf("ERROR; return code is %d\n", pt3);
    //     // printf("ERROR; return code is %d, %d, %d, %d\n\n", pt1, pt2, pt3, pt4);
    //     return EXIT_FAILURE;
    // }

    for(int i = 0; i < THREAD_NUM; i++)
    {
        pthread_join(thread[i], NULL);
    }
    return EXIT_SUCCESS;
}