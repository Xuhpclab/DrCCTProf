#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <vector>
#include <pthread.h>
using namespace std;


static int t1_sub_fun_call_num = 0;
void t1_sub_fun_1() {
    // printf("t1_sub_fun_1\n");
    // for(int i = 0; i < 10; i++){
         t1_sub_fun_call_num ++;
    // }
    return;
}

void t1_sub_fun_2() {
    // printf("t1_sub_fun_2\n");
    t1_sub_fun_call_num ++;
    return;
}

void t1_fun1() {
    for(int i = 0; i < 10000; i++){
        t1_sub_fun_1();
    }
}

void t1_fun2() {
    // t1_sub_fun_1();
}

void test_1()
{
    t1_fun1();
    t1_fun2();

    printf("t1_sub_fun_call_num %d\n", t1_sub_fun_call_num);
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

void test_2()
{
    t2_fun1();
    t2_fun2();
}

int* t3_memory_create()
{
    return (int*)malloc(100*sizeof(int)); 
}

void t3_memory_free(int* array)
{
    free((void*)array);
}

int global_int = 1024;
void test_3()
{
    int** int_tensor = (int**)malloc(100*sizeof(int*));
    for(int i = 0; i < 100; i++){
        int_tensor[i] = t3_memory_create();
    }
    for (int i = 0; i < 100; i++) {
        for(int j = 0; j < 100; j++){
            int_tensor[i][j] = global_int;
            printf("thread_4 init int_tensor[%d][%d]\n", i, j);
        }
    }
    for(int i = 0; i < 100; i++){
        t3_memory_free(int_tensor[i]);
    }
    free((void*)int_tensor);
}
#define THREAD_NUM 1
int main(){
    test_1();
    // test_2();
    // test_3();
    return EXIT_SUCCESS;
}