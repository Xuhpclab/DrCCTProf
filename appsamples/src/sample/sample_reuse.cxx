#include <stdio.h>
#include <stdlib.h>

typedef struct _mem_sub_sample_t
{
    int value;
} mem_sub_sample_t;

typedef struct _mem_sample_t
{
    mem_sub_sample_t* buff;
} mem_sample_t;

mem_sample_t* array;
// mem_sample_t* array2;
int g;

#define ARRAY_NUM 10000
#define ARRAY_BUFF_NUM 100

void test_fun1() {
    array = (mem_sample_t*)calloc(ARRAY_NUM, sizeof(mem_sample_t));
    // array2 = (mem_sample_t*)calloc(ARRAY_NUM, sizeof(mem_sample_t));
    for(int i = 0; i < ARRAY_NUM; i++) {
        array[i].buff = (mem_sub_sample_t*)calloc(ARRAY_BUFF_NUM, sizeof(mem_sub_sample_t));
        for(int j = 0; j < ARRAY_BUFF_NUM; j++) {
            array[i].buff[j].value =  i * j;
        }
    }
    // for(int i = 0; i < ARRAY_NUM; i++) {
    //     array2[i].buff = (mem_sub_sample_t*)calloc(ARRAY_BUFF_NUM, sizeof(mem_sub_sample_t));
    //     for(int j = 0; j < ARRAY_BUFF_NUM; j++) {
    //         array2[i].buff[j].value =  i * j;
    //     }
    // }
}

void test_fun2() {
    for(int i = 0; i < ARRAY_NUM; i ++) {
        for(int j = 0; j < ARRAY_BUFF_NUM; j++) {
            array[i].buff[j].value =  i * j;
        }
    }
}

void test_fun3() {
    for(int i = 0; i < ARRAY_NUM; i ++) {
        for(int j = 0; j < ARRAY_BUFF_NUM; j++) {
            // array2[i].buff[j].value =  array[i].buff[j].value;
            g += array[i].buff[j].value;
        }
    }
}


int main(){
    test_fun1();
    test_fun2();
    test_fun3();
    return 0; 
}