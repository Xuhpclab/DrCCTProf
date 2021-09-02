/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <stdio.h>
static int exe_num = 0;
void moo() {
    for(int i = 0; i < 100; i++){
        exe_num ++;
    }
    return;     
}
void foo() {
    for(int i = 0; i < 10000; i++){
        moo();
    }
}
int main(){
    foo();
    for(int i = 0; i < 20000; i++){
        moo();
    }
    return 0;  
}