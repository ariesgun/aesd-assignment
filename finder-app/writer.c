#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/*

Accepts the following arguments: 
the first argument is a full path to a file 
(including filename) on the filesystem, 
referred to below as writefile; 

the second argument is a text string which will be
written within this file, referred to below as 
writestr

Exits with value 1 error and print statements 
if any of the arguments above were not specified

Creates a new file with name and path writefile 
with content writestr, overwriting any existing 
file.
Exits with value 1 and error print statement if
 the file could not be created.

*/

int main (int argc, char *argv[])
{
    openlog(NULL, 0, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
        return 1;
    }

    const char* writefile = argv[1];
    const char* writestr = argv[2];

    int fd;
    fd = open(writefile, O_WRONLY | O_CREAT | O_TRUNC, 066);
    if (fd == -1) {
        syslog(LOG_ERR, "Unable to create file: %s", writefile);
        return 1;
    }

    ssize_t nr;

    nr = write(fd, writestr, strlen(writestr));
    if (nr == -1) {
        syslog(LOG_ERR, "Unable to write %s into file: %s", writestr, writefile);
        return 1;
    } else if (nr != strlen(writestr)) {
        syslog(LOG_ERR, "Writing %s into file not complete: %s", writestr, writefile);
        return 1;
    }

    return 0;
}