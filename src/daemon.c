#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>

#include "config.h"

extern void create_server(const char *path);
extern void stop_server();
extern void destroy_socket();

int running = 0;

static int pid_fd = -1;
static const char *app_name = NULL;

static char *get_home()
{
    char *buf = NULL;
    buf = (char *)malloc(512);
    if (buf != NULL)
    {
        snprintf(buf, 512, "/var/lib/%s", app_name);
    }
    return buf;
}

static void home_dir_check(const char *home)
{
    if (home)
    {
        struct stat st = {0};
        if (stat(home, &st) == -1)
        {
            mkdir(home, 0755);
        }
    }
}

static char *get_pid_file_name()
{
    char *buf = NULL;
    buf = (char *)malloc(512);
    if (buf != NULL)
    {
        snprintf(buf, 512, "/run/%s.pid", app_name);
    }
    return buf;
}

static char *get_socket_file_name()
{
    char *buf = NULL;
    buf = (char *)malloc(512);
    if (buf != NULL)
    {
        snprintf(buf, 512, "/var/lib/%s/sock", app_name);
    }
    return buf;
}

void handle_signal(int sig)
{
    int res;
    if (sig == SIGINT)
    {
        syslog(LOG_DEBUG, "Stopping daemon");
        if (pid_fd != -1)
        {
            if(lockf(pid_fd, F_ULOCK, 0) != 0)
            {
                syslog(LOG_ERR, "lockf");
            }
            close(pid_fd);
        }
        char *pid_file = get_pid_file_name();
        if (pid_file != NULL)
        {
            unlink(pid_file);
            free(pid_file);
        }

        running = 0;
        stop_server();
        destroy_socket();
    }
    else if (sig == SIGHUP)
    {
        syslog(LOG_DEBUG, "Reloading daemon config file");
    }
    else if (sig == SIGCHLD)
    {
        syslog(LOG_DEBUG, "Received SIGCHLD signal");
    }
    else if (sig == SIGPIPE)
    {
        syslog(LOG_DEBUG, "Received SIGPIPE signal");
    }
    else
    {
        syslog(LOG_DEBUG, "Received %d signal", sig);
    }
}

static void daemonize()
{
    pid_t pid = 0;
    int fd;

    pid = fork();

    if (pid < 0)
    {
        syslog(LOG_ERR, "Cann't fork");
        exit(EXIT_FAILURE);
    }

    if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0)
    {
        syslog(LOG_ERR, "Cann't set sid");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    umask(0);

    char *home = get_home();
    home_dir_check(home);
    if(chdir(home) != 0)
    {
        syslog(LOG_ERR, "Cann't change home dir to: %s", home);
    }
    free(home);

    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
    {
        close(fd);
    }

    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");

    char *buf = get_pid_file_name();
    if (buf != NULL)
    {
        pid_fd = open(buf, O_RDWR | O_CREAT, 0640);
        if (pid_fd < 0)
        {
            syslog(LOG_ERR, "Cann't open lock file: %s", buf);
            exit(EXIT_FAILURE);
        }
        if (lockf(pid_fd, F_TLOCK, 0) < 0)
        {
            syslog(LOG_ERR, "Cann't lock");
            exit(EXIT_FAILURE);
        }
        syslog(LOG_INFO, "Pid file %s", buf);
        sprintf(buf, "%d\n", getpid());
        if(write(pid_fd, buf, strlen(buf)) != strlen(buf))
        {
            syslog(LOG_ERR, "Cann't write pid");
        }
        free(buf);
    }
    else
    {
        syslog(LOG_ERR, "Cnan't write pid file");
    }
}

void print_help(void)
{
    printf("\n Usage: %s [OPTIONS]\n\n", app_name);
    printf("  Options:\n");
    printf("   -h --help                 Print this help\n");
    printf("   -d --daemon               Daemonize this application\n");
    printf("\n");
}

extern void scan_stop();

int main(int argc, char *argv[])
{
    static struct option long_options[] =
    {
        {"home", required_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {"daemon", no_argument, 0, 'd'},
        {NULL, 0, 0, 0}
    };
    int value, option_index = 0;
    int start_daemonized = 0;

    app_name = basename(argv[0]);

    while ((value = getopt_long(argc, argv, "H:dh", long_options, &option_index)) != -1)
    {
        switch (value)
        {
            case 'd':
                start_daemonized = 1;
                break;
            case 'h':
            case '?':
                print_help();
                return EXIT_SUCCESS;
            default:
                print_help();
                return EXIT_FAILURE;
        }
    }

    if (start_daemonized == 1)
    {
        daemonize();
    }

    openlog(app_name, LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Started %s", app_name);

    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGPIPE, handle_signal);

    running = 1;

    create_server(get_socket_file_name());

    syslog(LOG_INFO, "Stopped %s", app_name);
    closelog();

    return EXIT_SUCCESS;
}
