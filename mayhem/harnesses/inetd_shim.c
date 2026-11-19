/*
 * inetd_shim.c — input delivery for the pure-ftpd targets. Linked into a copy of the real
 * pure-ftpd binary (mayhem/build.sh relinks upstream's own objects with this file), it mocks
 * the superserver: pure-ftpd runs a single FTP session on fd 0 when fd 0 is a connected
 * socket (check_standalone() in src/ftpd.c, "inetd mode"). Before main() runs, this
 * constructor
 *   - takes the FTP control-connection bytes from stdin (the fuzz input), or, when
 *     FTPD_SHIM_SCRIPT is set, from that string (C escapes \r \n \t \\ are decoded) so a
 *     target can fuzz a file argument (config file, .pdb) with a fixed client session;
 *   - opens a TCP connection over 127.0.0.1 (pure-ftpd needs an AF_INET peer for its address
 *     checks), queues those bytes on the client side and half-closes it (EOF after the last
 *     command), and dup2()s the server side onto fd 0.
 * Nothing is patched: main(), option parsing and the whole session are upstream's code.
 * With FTPD_SHIM_ECHO=1 (mayhem/test.sh only, never the fuzz targets) a forked copy relays the
 * server's replies to stdout so the functional tests can assert them.
 * When stdin already is a socket (a real inetd), it does nothing.
 *
 * Per-input file state (fuzz targets only; mayhem/test.sh does not set it): when FTPD_SHIM_HOME
 * names a directory (the Mayhemfiles set /tmp/pure-ftpd-home, the home the PureDB seeds use), the
 * constructor empties it (creating it if missing) before the session. A login with a
 * quota makes pure-ftpd create and rewrite <home>/.ftpquota (quota_update() in src/quotas.c), so
 * without this each input would read the counts the inputs before it left there. It also removes
 * .ftpquota from the other directories the fuzz user can write (reset_file_state()).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_SESSION (128U * 1024U)

static int client_keep = -1;   /* the client end stays open so replies have somewhere to go */

static size_t unescape(const char *s, unsigned char *out, size_t max)
{
    size_t n = 0;
    while (*s != 0 && n < max) {
        if (s[0] == '\\' && s[1] != 0) {
            switch (s[1]) {
            case 'r': out[n++] = '\r'; break;
            case 'n': out[n++] = '\n'; break;
            case 't': out[n++] = '\t'; break;
            default:  out[n++] = (unsigned char) s[1]; break;
            }
            s += 2;
        } else {
            out[n++] = (unsigned char) *s++;
        }
    }
    return n;
}

static int rm_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void) st; (void) flag;
    if (ftw->level == 0) {
        return 0;       /* keep the directory itself, only empty it */
    }
    return remove(path) == 0 ? 0 : -1;
}

/*
 * Reset the file state a login can leave: FTPD_SHIM_HOME (the home the PureDB seeds name) is
 * created if missing and emptied, and a .ftpquota in the other directories the fuzz user can write
 * (cwd, $TMPDIR or /tmp, $HOME) is removed, so a record whose home was mutated to one of
 * those doesn't hand its quota counts to the next input either.
 */
static void reset_file_state(const char *home)
{
    const char *dirs[3];
    char path[4096];

    struct stat st;

    /* World-writable, not sticky, so a later run under another uid can still empty it. */
    if (mkdir(home, 0777) == 0) {
        (void) chmod(home, 0777);
    } else if (errno != EEXIST || stat(home, &st) != 0 || !S_ISDIR(st.st_mode)) {
        abort();
    }
    if (nftw(home, rm_entry, 16, FTW_DEPTH | FTW_PHYS) != 0) {
        abort();
    }
    dirs[0] = ".";
    dirs[1] = getenv("TMPDIR") != NULL && *getenv("TMPDIR") != 0 ? getenv("TMPDIR") : "/tmp";
    dirs[2] = getenv("HOME");
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (dirs[i] != NULL && *dirs[i] != 0 &&
            (size_t) snprintf(path, sizeof path, "%s/.ftpquota", dirs[i]) < sizeof path) {
            (void) unlink(path);
        }
    }
}

__attribute__((constructor))
static void ftpd_inetd_shim(void)
{
    static unsigned char buf[MAX_SESSION];
    size_t len = 0;
    struct stat st;
    struct sockaddr_in sa;
    socklen_t salen = sizeof sa;
    const char *script = getenv("FTPD_SHIM_SCRIPT");
    const char *home = getenv("FTPD_SHIM_HOME");
    int lfd, cfd, sfd, one = 1, big = 1 << 20;

    if (fstat(0, &st) == 0 && S_ISSOCK(st.st_mode)) {
        return;
    }
    if (home != NULL && *home != 0) {
        reset_file_state(home);
    }
    if (script != NULL) {
        len = unescape(script, buf, sizeof buf);
    } else {
        ssize_t r;
        while (len < sizeof buf && (r = read(0, buf + len, sizeof buf - len)) > 0) {
            len += (size_t) r;
        }
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        bind(lfd, (struct sockaddr *) &sa, sizeof sa) != 0 ||
        listen(lfd, 1) != 0 ||
        getsockname(lfd, (struct sockaddr *) &sa, &salen) != 0 ||
        (cfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        abort();
    }
    (void) setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void) setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    if (connect(cfd, (struct sockaddr *) &sa, sizeof sa) != 0 ||
        (sfd = accept(lfd, NULL, NULL)) == -1) {
        abort();
    }
    close(lfd);
    (void) setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    (void) fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);
    for (size_t off = 0; off < len; ) {
        ssize_t w = write(cfd, buf + off, len - off);
        if (w <= 0) {
            break;      /* socket buffers full: the rest of an oversized input is dropped */
        }
        off += (size_t) w;
    }
    (void) shutdown(cfd, SHUT_WR);
    if (getenv("FTPD_SHIM_ECHO") != NULL && strcmp(getenv("FTPD_SHIM_ECHO"), "1") == 0) {
        pid_t pid = fork();
        if (pid == -1) {
            abort();
        }
        if (pid == 0) {
            ssize_t r;
            close(sfd);
            (void) fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) & ~O_NONBLOCK);
            while ((r = read(cfd, buf, sizeof buf)) > 0) {
                if (write(1, buf, (size_t) r) != r) {
                    break;
                }
            }
            _exit(0);
        }
    }
    if (dup2(sfd, 0) == -1) {
        abort();
    }
    close(sfd);
    client_keep = cfd;
}
