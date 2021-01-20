/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int global_num = 0;
void sig_callback(int signum) {
    switch (signum) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGCONT:
        case SIGINT:
            global_num ++;
            break;
        default:
            break;
    }

    return;
}

void registe_singal(int singnum) {
    printf("Register SIG(%u) Signal Action. \r\n", singnum);
    signal(singnum, sig_callback);
}

int main(int argc, char *argv[]) {
    printf("process is %d \r\n", getpid());
    
    registe_singal(SIGSTOP);
    registe_singal(SIGTSTP);
    registe_singal(SIGCONT);
    registe_singal(SIGINT);
    
    while(global_num <= 1111){
        raise(SIGINT);
        pause();
    }
    printf("global_num %d \r\n", global_num);
    // for(int i = 0; i < 2222; i++){
    //     raise(SIGSTOP);
    //     raise(SIGCONT);
    // }
    // for(int i = 0; i < 3333; i++){
    //     raise(SIGTSTP);
    //     raise(SIGCONT);
    // }
    return 0;
}