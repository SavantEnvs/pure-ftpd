/*
 * libFuzzer harness for the PureDB reader's public API (puredb/src/puredb_read.h),
 * the same sequence puredb/src/example_read.c and the server's puredb auth backend
 * (src/log_puredb.c) use: puredb_open -> puredb_find_s -> puredb_read -> puredb_close.
 *
 * Input layout: byte 0 = key length N, bytes 1..N = the key to look up, the rest = the
 * .pdb file. The reader only opens files by path, so the database bytes are written to a
 * private temp file under $TMPDIR (rewritten per input; nothing else is kept between inputs).
 */
#include <config.h>
#include "puredb_p.h"
#include "puredb_read.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char db_path[4096];
static int db_fd = -1;

static int write_db(const uint8_t *data, size_t size)
{
    if (db_fd == -1) {
        const char *tmp = getenv("TMPDIR");
        if (tmp == NULL || *tmp == 0) {
            tmp = "/tmp";
        }
        snprintf(db_path, sizeof db_path, "%s/fuzz_puredb_XXXXXX", tmp);
        if ((db_fd = mkstemp(db_path)) == -1) {
            abort();
        }
    }
    if (ftruncate(db_fd, 0) != 0 || lseek(db_fd, 0, SEEK_SET) != 0) {
        abort();
    }
    while (size > 0) {
        ssize_t w = write(db_fd, data, size);
        if (w <= 0) {
            abort();
        }
        data += w;
        size -= (size_t) w;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    PureDB db;
    char key[256];
    size_t klen;
    off_t off;
    size_t len;
    int ret;

    if (size < 1) {
        return -1;
    }
    klen = data[0];
    if (size < 1 + klen) {
        return -1;
    }
    memcpy(key, data + 1, klen);
    key[klen] = 0;          /* puredb_find_s takes a C string */
    write_db(data + 1 + klen, size - 1 - klen);

    ret = puredb_open(&db, db_path);
    if (ret == -1 || ret == -2) {
        /* puredb_open already released the fd and mapped nothing */
        return 0;
    }
    if (ret == 0 && puredb_find_s(&db, key, &off, &len) == 0) {
        char *found = puredb_read(&db, off, len);
        if (found != NULL) {
            volatile size_t sum = 0;
            for (size_t i = 0; i < len; i++) {
                sum += (unsigned char) found[i];
            }
            (void) sum;
            puredb_read_free(found);
        }
    }
    puredb_close(&db);
    return 0;
}
