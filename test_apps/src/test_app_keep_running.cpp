/*
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <unistd.h>
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

int
main(int argc, char *argv[])
{
    cout << "process is " << getpid() << endl;
    
    while (true) {
        char input = 0;
        cout << "Enter a value :" << endl;
        cin >> input;
        if(input == 'q') {
            break;
        } else {
            int i = 0;
            while (i < 500000) {
                i++;
                Function();
            }
            cout << "SubFunctionA " << sub_fun_call_num_a << endl;
            cout << "SubFunctionB " << sub_fun_call_num_b << endl;
            cout << "SubSubFunction " << sub_sub_fun_call_num << endl;
        }  
    }
    return 0;
}