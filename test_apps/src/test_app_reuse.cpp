/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <stdio.h>
#include <stdlib.h>

int* array;
// mem_sample_t* array2;
int g;

#define ARRAY_NUM 10000

void test_fun1() {
    array = (int*)malloc(ARRAY_NUM * sizeof(int));
    for(int i = 0; i < ARRAY_NUM; i++) {
        array[i] = i;
    }
}

void test_fun2() {
    int test_fun2 = 0;
    for(int i = 0; i < ARRAY_NUM; i ++) {
        test_fun2 += array[i];
    }
}

void test_fun3() {
    int test_fun3 = 0;
    for(int i = 0; i < ARRAY_NUM; i ++) {
        test_fun3 += array[i];
    }
}


int main(){
    test_fun1();
    for(int i =0 ; i < 100; i++) {
        test_fun2();
        test_fun3();
    }
    return 0; 
}