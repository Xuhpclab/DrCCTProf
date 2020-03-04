#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <vector>
#include <pthread.h>
using namespace std;


static int sub_fun_call_num = 0;
void t1_sub_fun() {
    sub_fun_call_num ++;
    return;
}

void t2_sub_fun() {
    sub_fun_call_num ++;
    return;
}

void t1_fun() {
    for(int i = 0; i < 22222222; i++){
        t1_sub_fun();
    }
}

void t2_fun() {
    for(int i = 0; i < 11111111; i++){
        t2_sub_fun();
    }
}

void *thread_1(void *arg)
{
    t1_fun();
}

void *thread_2(void *arg)
{
    t2_fun();
}


int main(){
    // t1_fun();
    t2_fun();
    // int pt1, pt2;
    // // int pt3;
    // pthread_t thread[2];
    // pt1 = pthread_create(&thread[0], NULL, thread_1, NULL);
    // pt2 = pthread_create(&thread[1], NULL, thread_2, NULL);

    // if (pt1)
    // {
    //     printf("ERROR; return code is %d\n", pt1);
    //     // printf("ERROR; return code is %d, %d, %d, %d\n\n", pt1, pt2, pt3, pt4);
    //     return EXIT_FAILURE;
    // }
    // if (pt2)
    // {
    //     printf("ERROR; return code is %d\n", pt1);
    //     // printf("ERROR; return code is %d, %d, %d, %d\n\n", pt1, pt2, pt3, pt4);
    //     return EXIT_FAILURE;
    // }
    // for(int i = 0; i < 2; i++)
    // {
    //     pthread_join(thread[i], NULL);
    // }

    printf("sub_fun_call_num %d\n", sub_fun_call_num);
    return EXIT_SUCCESS;
}