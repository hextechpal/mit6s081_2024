#include "kernel/types.h"
#include "user/user.h"

const int READ = 0;
const int WRITE = 1;

void generate(int[2]) __attribute__((noreturn));

int main(int argc, char *argv[]){
    int p[2];

    if(pipe(p) == -1){
        fprintf(2, "error creating pipe");
        exit(1);
    }

    int child = fork();

    if(child < 0){
        fprintf(2, "error forking child");
        close(p[READ]);
        close(p[WRITE]);
        exit(1);
    }else if(child == 0){
        generate(p);
    }else{
        close(p[READ]);
        for(int i=2; i<=280; i++){
            write(p[WRITE], &i, sizeof(int));
        }
        close(p[WRITE]);
        wait(0);
    }
    exit(0);
}

void generate(int left[2]){
    close(left[WRITE]);
    int prime;
    if(read(left[READ], &prime, sizeof(int)) == 0){
        close(left[READ]);
        exit(0);
    }
    fprintf(1, "prime %d\n", prime);

    int next;
    int right[2];
    pipe(right);
    int child = fork();
    if(child > 0){
        close(right[READ]);
        while(read(left[READ], &next, sizeof(int)) > 0){
            if(next % prime != 0){
                write(right[WRITE], &next, sizeof(int));
            }
        }
        close(right[WRITE]);
        close(left[READ]);
        wait(0);
        exit(0);
    }else if(child == 0){
        close(left[READ]);
        generate(right);
        exit(0);
    }else{
        close(left[READ]);
        close(right[READ]);
        close(right[WRITE]);
        fprintf(2, "cannot fork child");
        exit(1);
    }
       
}

