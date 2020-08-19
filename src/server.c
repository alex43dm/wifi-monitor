#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>

#include <glib.h>
#include <NetworkManager.h>

#include <pthread.h>

#include "def.h"

#define MAX_CLIENTS 5
#define MAX_BUFFER_LEN 1024
#define CMD_LEN 1024

extern int running;
extern void create_server(const char *path);

static int sock = 0;
static const char *path = NULL;
static const char *iface = NULL;
static const char *ap = NULL;
static int scanning = 0;
static int wifi_stoped = 0;
static pthread_t tid = 0;

enum
{
    START_WIFI,
    STOP_WIFI,
    START_SCAN,
    STOP_SCAN,
    UNUSED
} cmd;

int decode(const char *buf, int len)
{
    if (strncmp(buf, "START_WIFI", len) == 0)
    {
        syslog(LOG_DEBUG, "START WIFI");
        return START_WIFI;
    }
    else if (strncmp(buf, "STOP_WIFI", len) == 0)
    {
        syslog(LOG_DEBUG, "STOP WIFI");
        return STOP_WIFI;
    }
    else if (strncmp(buf, "START_SCAN", len) == 0)
    {
        syslog(LOG_DEBUG, "START SCAN");
        return START_SCAN;
    }
    else if (strncmp(buf, "STOP_SCAN", len) == 0)
    {
        syslog(LOG_DEBUG, "STOP SCAN");
        return STOP_SCAN;
    }
    return UNUSED;
}

static void wifi_device_info (NMDevice *device, const char **iface, const char **ap)
{
    NMAccessPoint *active_ap = NULL;
    GBytes *active_ssid;

    if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
    {
        if ((active_ap = nm_device_wifi_get_active_access_point (NM_DEVICE_WIFI (device))))
        {
            active_ssid = nm_access_point_get_ssid (active_ap);
            if (active_ssid)
            {
                *ap = strdup(nm_utils_ssid_to_utf8 (g_bytes_get_data (active_ssid, NULL),
                                                    g_bytes_get_size (active_ssid)));
            }
        }
    }

    *iface = strdup(nm_device_get_iface (device));
}

int nm_get_wifi()
{
    NMClient *client;
    client = nm_client_new (NULL, NULL);
    if (!client)
    {
        syslog(LOG_ERR, "Cann't get NetworkManager client");
        return 1;
    }

    if (!nm_client_get_nm_running (client))
    {
        syslog(LOG_ERR, "Can't obtain devices: NetworkManager is not running.");
        g_object_unref (client);
        return 1;
    }

    syslog(LOG_DEBUG, "NetworkManager version: %s", nm_client_get_version (client));

    const GPtrArray *devices;
    devices = nm_client_get_devices (client);
    for (guint i = 0; i < devices->len; i++)
    {
        NMDevice *device = g_ptr_array_index (devices, i);
        if (NM_IS_DEVICE_WIFI (device))
        {
            wifi_device_info(device, &iface, &ap);
            syslog(LOG_DEBUG, "Found wifi dev: %s AP: %s", iface, ap);
        }
    }

    g_object_unref(client);

    return 0;
}

static int exec_cmd(char *cmd)
{
    FILE *pipe_fp;
    if ((pipe_fp = popen(cmd, "r")) == NULL)
    {
        syslog(LOG_ERR, "cmd: %s", cmd);
        return 1;
    }

    fread(cmd, CMD_LEN, 1, pipe_fp);
    pclose(pipe_fp);

    syslog(LOG_DEBUG, "Run cmd: %s done", cmd);

    return 0;
}

int wifi(int flag)
{
    nm_get_wifi();

    if (!iface)
    {
        syslog(LOG_ERR, "Can't obtain wifi device");
        return 1;
    }

    char *cmd = NULL;
    cmd = (char *)malloc(CMD_LEN);
    if (!cmd)
    {
        syslog(LOG_ERR, "Cann't alloc");
        return 1;
    }

    if (flag)
    {
        if (wifi_stoped == 0)
        {
            snprintf(cmd, CMD_LEN - 1, "%s link set %s down", IP, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s %s set type managed", IW, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s link set %s up", IP, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s device set %s managed on", NMCLI, iface);
            if (exec_cmd(cmd)) goto err;
            wifi_stoped = 1;
        }
    }
    else
    {
        if (wifi_stoped == 1)
        {
            snprintf(cmd, CMD_LEN - 1, "%s device set %s managed off", NMCLI, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s link set %s down", IP, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s %s set monitor none", IW, iface);
            if (exec_cmd(cmd)) goto err;
            snprintf(cmd, CMD_LEN - 1, "%s link set %s up", IP, iface);
            if (exec_cmd(cmd)) goto err;
            wifi_stoped = 0;
        }
    }

    free(cmd);
    return 0;
err:
    free(cmd);
    return 1;
}

void *scan_routine(void *params)
{
    (void)params;
    FILE *pipe_fp;
    char *cmd = NULL;

    syslog(LOG_DEBUG, "Start scan routine");

    cmd = (char *)malloc(CMD_LEN);
    if (!cmd)
    {
        syslog(LOG_ERR, "Cann't alloc");
        return NULL;
    }

    snprintf(cmd, CMD_LEN - 1, "%s -w dump -I 1 %s", AIRODUMP_NG, iface);

    syslog(LOG_DEBUG, "run cmd: %s", cmd);

    if ((pipe_fp = popen(cmd, "w")) == NULL)
    {
        syslog(LOG_ERR, "cmd: %s", cmd);
        return NULL;
    }

    while (scanning)
    {
        sleep(1);
    }

    syslog(LOG_DEBUG, "stop scan");

    fwrite("q\nq\n", 4, 1, pipe_fp);
    free(cmd);
    pclose(pipe_fp);

    syslog(LOG_DEBUG, "exit scan");
    pthread_exit(NULL);
}

int wifi_check_mode()
{
    char *buf = NULL;
    buf = (char *)malloc(CMD_LEN);
    if (!buf)
    {
        syslog(LOG_ERR, "Cann't alloc");
        return 1;
    }
    snprintf(buf, CMD_LEN - 1, "/sys/class/net/%s/type", iface);
    int fd;
    fd = open(buf, O_RDONLY);
    if (!fd)
    {
        syslog(LOG_ERR, "open: %s", buf);
        free(buf);
        return 1;
    }

    int res = read(fd, buf, CMD_LEN);

    close(fd);

    if (!res)
    {
        syslog(LOG_ERR, "read file: %d", res);
        free(buf);
        return 1;
    }


    res = strtol(buf, NULL, 10);
    if (res != 803)
    {
        syslog(LOG_ERR, "wifi state: %d", res);
        free(buf);
        return 1;
    }

    free(buf);
    return 0;
}

int scan()
{
    if (scanning)
    {
        syslog(LOG_ERR, "Already scanning");
        return 1;
    }

    if (!iface)
    {
        nm_get_wifi();
        if (!iface)
        {
            syslog(LOG_ERR, "Can't obtain wifi device");
            return 1;
        }
    }

    if (wifi_check_mode())
    {
        syslog(LOG_ERR, "Can't wifi device not in monitor mode");
        return 1;
    }

    scanning = 1;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&tid, &attr, scan_routine, NULL);

    return 0;
}

void scan_stop()
{
    sleep(27);
    scanning = 0;
    pthread_join(tid, NULL);
}


void destroy_socket()
{
    close(sock);
    unlink(path);
}

void *handle_client(void *data)
{
    int *s = (int *) data;
    char *buf = NULL;
    int len = 0;

    syslog(LOG_DEBUG, "Starting communication with a client");

    buf = (char *) calloc(1, MAX_BUFFER_LEN);
    if (!buf)
    {
        syslog(LOG_ERR, "Cann't alloc");
        goto err;
    }

    len = recv(*s, buf, MAX_BUFFER_LEN, 0);

    close(*s);

    if (len <= 0)
    {
        if (errno == ENOENT)
        {
            syslog(LOG_ERR, "Client socket was closed by peer");
        }
        else
        {
            syslog(LOG_ERR, "Failed read(%d) from socket (%d: %s)",
                   len,
                   errno,
                   errno ? strerror(errno) : "No input on socket");
        }
    }
    else
    {
//        syslog(LOG_DEBUG, "Incoming message: len:%d data:%s", len, buf);
        switch (decode(buf, len))
        {
            case START_WIFI:
                wifi(1);
                break;
            case STOP_WIFI:
                wifi(0);
                break;
            case START_SCAN:
                scan();
                break;
            case STOP_SCAN:
                scanning = 0;
                break;
            default:
                syslog(LOG_DEBUG, "Unknow command");
                break;
        }
    }
    free(buf);
err:
    free(data);
    syslog(LOG_DEBUG, "Communication with client ended");
    pthread_exit(NULL);
}

void create_server(const char *path)
{
    path = path;
    int res = 0;
    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        syslog(LOG_ERR, "Failed creating a new socket");
        exit(EXIT_FAILURE);
    }

    unlink(path);

    memset(&addr, 0x00, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path));

    res = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0)
    {
        syslog(LOG_ERR, "Failed binding socket to %s (%d: %s)", path, errno, strerror(errno));
        destroy_socket();
        exit(EXIT_FAILURE);
    }

    res = listen(sock, MAX_CLIENTS);
    if (res < 0)
    {
        syslog(LOG_ERR, "Failed listening on socket (%d: %s)", errno, strerror(errno));
        destroy_socket();
        exit(EXIT_FAILURE);
    }

    while (running)
    {
        struct sockaddr a;
        socklen_t len = sizeof(a);
        int *s = (int *)malloc( sizeof(int));
        *s = accept(sock, &a, &len);
        syslog(LOG_DEBUG, "Accept client: %d", *s);
        if (*s < 0)
        {
            syslog(LOG_ERR, "Failed accepting client (%d: %s)", errno, strerror(errno));
            destroy_socket();
            exit(EXIT_FAILURE);
        }
        pthread_t _tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&_tid, &attr, handle_client, (void *)s);
    }
}

void stop_server()
{
    write(sock, "STOP\n", 7);
}
