// #include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
// using namespace std;

// int MyArray[10];
int global_int = 0;

int * Create(){
    return (int *)malloc(10 * sizeof(int));
}

void ExceptionTest() {
    global_int ++;
    if (global_int > 6) {
        throw "global_ini > 6";
    }
}

void DataCreate() {
    int * p;
    p = Create();
    ExceptionTest();
}

void SubFun1() {
    // cout<<"SubFun1()"<<endl;
    try {
        DataCreate();
    }catch (const char* msg) {
    //  cerr << msg << endl;
    }
    
}

void SubFun2() {
    // cout<<"SubFun2()"<<endl;
    DataCreate();
}

void Fun1() {
    // cout<<"Fun1()"<<endl;
    SubFun1();
}

void Fun2() {
    // cout<<"Fun2()"<<endl;
    try {
        SubFun2();
    }catch (const char* msg) {
    //  cerr << msg << endl;
    }
}

void Fun3() {
    SubFun2();
}

int main(){
    Fun1();
    Fun2();
    try {
        Fun3();
    }catch (const char* msg) {
    //  cerr << msg << endl;
    }
}