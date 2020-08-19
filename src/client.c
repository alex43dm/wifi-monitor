#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static int socket_connect(int sock, const char *socket_name)
{
    struct sockaddr_un address;

    memset(&address, 0x00, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_name, strlen(socket_name));

    return connect(sock, (struct sockaddr *)&address, sizeof(address));
}

int socket_open(const char *path)
{
    int res;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    res = socket_connect(sock, path);
    if (res < 0)
    {
        printf("Failed connect socket to %s (%d: %s)", path, errno, strerror(errno));
        close(sock);
        return res;
    }

    return sock;
}

void socket_close(int sock)
{
    if (sock > 0)
        close(sock);
}

int socket_read(int sock, char *buff, int len)
{
    return read(sock, buff, len);
}

int socket_write(int sock, const char *buff, int len)
{
    return write(sock, buff, len);
}

int main(int argc, char *argv[])
{
    char *path = "/var/lib/wifi-monitor/sock";
    int sock;

    if (argc < 2)
    {
        printf("Usage: %s <data>\n", argv[0]);
        return 0;
    }

    char *data = argv[1];
    sock = socket_open(path);
    if (sock < 0)
    {
        printf("Failed opening socket %s\n", path);
        return 1;
    }

    if (socket_write(sock, data, strlen(data)) < 0)
    {
        printf("Error writing to socket\n");
        socket_close(sock);
        return 1;
    }

    //socket_close(sock);

    return 0;
}
