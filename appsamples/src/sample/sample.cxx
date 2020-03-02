#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <vector>
#include <pthread.h>
using namespace std;


static int t1_sub_fun_call_num = 0;
void t1_sub_fun_1() {
    t1_sub_fun_call_num ++;
    return;
}

void t1_sub_fun_2() {
    t1_sub_fun_call_num ++;
    return;
}

void t1_fun1() {
    for(int i = 0; i < 10000000; i++){
        t1_sub_fun_1();
    }
}

void t1_fun2() {
    t1_sub_fun_2();
}

void test_1()
{
    t1_fun1();
    t1_fun2();
    // printf("t1_sub_fun_call_num %d\n", t1_sub_fun_call_num);
}

int main(){
    test_1();
    return EXIT_SUCCESS;
}