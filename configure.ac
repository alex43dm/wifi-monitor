AC_INIT([wifi-monitor], [1.0], [wvdial@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

dnl AC_PREFIX_DEFAULT(sbin)

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

AC_CHECK_HEADERS([stdlib.h unistd.h syslog.h signal.h getopt.h string.h \
fcntl.h sys/stat.h sys/types.h errno.h libgen.h sys/stat.h \
sys/socket.h sys/un.h sys/types.h arpa/inet.h stdlib.h glib.h NetworkManager.h pthread.h])

AC_PATH_PROG(PKG_CONFIG, pkg-config)

PKG_CHECK_MODULES([NM], [libnm])
AC_SUBST([NM_CFLAGS])
AC_SUBST([NM_LIBS])

CFLAGS="$CFLAGS $NM_CFLAGS"
LIBS="$LIBS $NM_LIBS"

dnl AC_DEFINE(DEBUG, 1, [debug mode])

AC_PATH_PROG(NMCLI,nmcli)
if test -z "$NMCLI"
then
    AC_MSG_ERROR([You need the nmcli from https://wiki.gnome.org/Projects/NetworkManager])
else
    AC_DEFINE_UNQUOTED(NMCLI, "$ac_cv_path_NMCLI", [nmcli path])
fi

AC_PATH_PROG(IP,ip)
if test -z "$IP"
then
    AC_MSG_ERROR([You need the ip from https://wiki.linuxfoundation.org/networking/iproute2])
else
    AC_DEFINE_UNQUOTED(IP, "$ac_cv_path_IP", [ip path])
fi


AC_PATH_PROG(IW,iw)
if test -z "$IW"
then
    AC_MSG_ERROR([You need the iw from https://wireless.wiki.kernel.org/en/users/Documentation/iw])
else
    AC_DEFINE_UNQUOTED(IW, "$ac_cv_path_IW", [iw path])
fi

AC_PATH_PROG(AIRODUMP_NG,airodump-ng)
if test -z "$AIRODUMP_NG"
then
    AC_MSG_ERROR([You need the airodump-ng http://www.aircrack-ng.org])
else
    AC_DEFINE_UNQUOTED(AIRODUMP_NG, "$ac_cv_path_AIRODUMP_NG", [airodump-ng path])
fi

AC_OUTPUT
