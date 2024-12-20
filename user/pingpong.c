#include "kernel/types.h"
#include "user/user.h"

int main(int argc, char *argv[]){

    int p1[2];
    int p2[2];
    if(pipe(p1) != 0 || pipe(p2) != 0){
        printf("failed to open a pipe");
        exit(1);
    }

    int child = fork();
    if(child < 0){
        close(p1[0]);
        close(p1[1]);
        close(p2[0]);
        close(p2[1]);
        fprintf(2, "failed to fork child process");
        exit(1);
    }else if(child == 0){
        close(p1[1]);
        close(p2[0]);
        char b;
        if(read(p1[0], &b, 1) != 0){
            fprintf(1, "%d: received ping\n", getpid());
        }
        write(p2[1], &b, 1);
        close(p1[0]);
        close(p2[1]);
    }else{
        close(p1[0]);
        close(p2[1]);
        write(p1[1], "a", 1);
        char b;
        if(read(p2[0], &b, 1) != 0){
            fprintf(1, "%d: received pong\n", getpid());
        }
        close(p2[0]);
        close(p1[1]);
        wait(0);

    }

    exit(0);

}