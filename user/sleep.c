#include "kernel/types.h"
#include "user/user.h"

int main(int argc, char *argv[]){
    if(argc != 2){
        fprintf(2, "invalid command. Usage sleep <time_in_seconds>");
        exit(1);
    }

    int duration = atoi(argv[1]);
    sleep(duration);
    exit(0);
}