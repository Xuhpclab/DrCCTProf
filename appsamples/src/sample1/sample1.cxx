#include <iostream>
#include <stdio.h>   
#include <stdlib.h> 
#include <vector>
using namespace std;

#define CATCH_IN_SubFun 0
#define CATCH_IN_Fun 1
#define CATCH_IN_Main 2
#define NO_CATCH 3
// int MyArray[10];
int global_int = 0;
class TestClass{
    public:
        int classIntValue;
};

struct TestWarpcontentArgs {
    int intValue;
    char *charPtrValue;
    vector<int> verctorValue;
    TestClass* userDefineClassPtrValue;
};


int TestWarp(TestWarpcontentArgs args0, TestWarpcontentArgs *args1){
    cerr << args0.userDefineClassPtrValue->classIntValue << endl;
    cerr<< args1->userDefineClassPtrValue->classIntValue << endl;

    return 100;
}

int * Create(){
    return (int *)malloc(10 * sizeof(int));
}

void ExceptionTest() {
    if (global_int > CATCH_IN_SubFun) {
        throw global_int;
    }
}

void DataCreate() {
    int * p;
    p = Create();
    p[5] = global_int;
    ExceptionTest();
}

void SubFun1() {
    // cout<<"SubFun1()"<<endl;
    try {
        global_int ++;
        DataCreate();
    }catch (int e) {
        cerr << "SubFun: global_int = " << e << endl;
    }
    
}

void SubFun2() {
    DataCreate();
}

void Fun1() {
    SubFun1();
}

void Fun2() {
    try {
        global_int ++;
        SubFun2();
    } catch (int e) {
        cerr << "Fun: global_int = " << e << endl;
    }
}

void Fun3() {
    SubFun2();
}

int main(){
    
    TestClass* testClass = new TestClass();
    TestClass* testClass1 = new TestClass();
    testClass->classIntValue = 11;
    testClass1->classIntValue = 22;
    TestWarpcontentArgs testStruct;
    testStruct.intValue = 1;
    testStruct.userDefineClassPtrValue = testClass;
    testStruct.verctorValue.push_back(2);
    testStruct.charPtrValue = (char*)malloc(10*sizeof(char));
    for (int i = 0; i < 9; i++) {
        testStruct.charPtrValue[i] = 'c';
    }
    testStruct.charPtrValue[9] = '\n';
    TestWarpcontentArgs testStruct1;
    testStruct1.intValue = 1;
    testStruct1.userDefineClassPtrValue = testClass1;
    testStruct1.verctorValue.push_back(2);
    testStruct1.charPtrValue = (char*)malloc(10*sizeof(char));
    for (int i = 0; i < 9; i++) {
        testStruct1.charPtrValue[i] = 'c';
    }
    testStruct1.charPtrValue[9] = '\n';
    
    TestWarp(testStruct, &testStruct1);

    Fun1();
    Fun2();
    try {
        global_int ++;
        Fun3();
    } catch (int e) {
        cerr << "main: global_int = " << e << endl;
    }
}