#include "kernel/types.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(2, "please pass a command to execute");
        exit(1);
    }

    char *eargs[argc + 1];

    for (int i = 1; i < argc; i++)
    {
        eargs[i - 1] = argv[i];
    }

    char buf[512];
    int buf_idx = 0;
    char curr;

    eargs[argc - 1] = buf;
    eargs[argc] = 0;

    while (read(0, &curr, 1) > 0)
    {
        if (curr == '\n' || curr == ' ')
        {
            buf[buf_idx] = 0;
            int child = fork();
            if (child == 0)
            {
                exec(eargs[0], eargs);
            }
            else if (child > 0)
            {
                wait(0);
                buf_idx = 0;
            }
            else
            {
                fprintf(2, "xargs: failed to fork child process");
                exit(1);
            }
        }
        else
        {
            buf[buf_idx] = curr;
            buf_idx++;
        }
    }
    exit(0);
}