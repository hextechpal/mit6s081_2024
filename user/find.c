#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "kernel/stat.h"
#include "kernel/fs.h"
#include "user/user.h"

void find(char *path, char *name)
{
    char buf[512];
    char *p;
    struct stat st;
    struct dirent de;
    int fd;

    if ((fd = open(path, O_RDONLY)) == -1)
    {
        fprintf(2, "cannot open directory %s\n", path);
        exit(1);
    }

    if (fstat(fd, &st) == -1)
    {
        fprintf(2, "cannot stat directory %s\n", path);
        close(fd);
        exit(1);
    }

    switch (st.type)
    {
    case T_FILE:
    case T_DEVICE:
        fprintf(2, "first argument should be a directory\n");
    case T_DIR:
        // DIRSIZ -> is max size of directory
        // +1 are for null terminator for c string
        // this implies if exploring this directory will blow off our buffer length nad hence no point
        if (strlen(path) + 1 + DIRSIZ + 1 > sizeof buf)
        {
            printf("find: path too long\n");
            break;
        }
        strcpy(buf, path);
        p = buf + strlen(buf);
        *p++ = '/';
        while (read(fd, &de, sizeof(de)) == sizeof(de))
        {
            if (de.inum == 0)
                continue;
            memmove(p, de.name, DIRSIZ);
            p[DIRSIZ] = 0;
            if (stat(buf, &st) < 0)
            {
                printf("find: cannot stat %s\n", buf);
                continue;
            }

            if (strcmp(de.name, ".") == 0 || strcmp(de.name, "..") == 0)
            {
                continue;
            }

            if (st.type == T_DIR)
            {
                find(buf, name);
            }
            else if (strcmp(de.name, name) == 0)
            {
                printf("%s/%s\n", path, de.name);
            }
        }
        break;
    }
    close(fd);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(2, "Usage find <dir> <file_name>");
        exit(1);
    }
    find(argv[1], argv[2]);
    exit(0);
}