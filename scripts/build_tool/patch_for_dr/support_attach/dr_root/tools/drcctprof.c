/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "configure.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include "globals_shared.h"
#include "dr_config.h"
#include "dr_frontend.h"
#include "drcct_attach.h"

static bool verbose;
static bool quiet;

#define die() exit(1)

#define fatal(msg, ...)                                     \
    do {                                                    \
        fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr);                                     \
        exit(1);                                            \
    } while (0)

/* up to caller to call die() if necessary */
#define error(msg, ...)                                     \
    do {                                                    \
        fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr);                                     \
    } while (0)

#define warn(msg, ...)                                            \
    do {                                                          \
        if (!quiet) {                                             \
            fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__); \
            fflush(stderr);                                       \
        }                                                         \
    } while (0)

#define info(msg, ...)                                         \
    do {                                                       \
        if (verbose) {                                         \
            fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__); \
            fflush(stderr);                                    \
        }                                                      \
    } while (0)

#define TOOLNAME "drcctprof"

const char *usage_str =
    "USAGE: " TOOLNAME " -attach <pid> [-ops options] -t <toolname> <options>*\n"
    "   or: " TOOLNAME " -attach <pid> [-ops options] -c <path> <options>*\n"
    "   or: " TOOLNAME " -detach <pid>\n";

const char *options_list_str =
    "\n" TOOLNAME " options (these are distinct from DR runtime options):\n"
    "       -version           Display version information\n"
    "       -verbose           Display additional information\n"
    "       -quiet             Do not display warnings\n"
    "       -debug             Use the DR debug library\n"
    "\n"
    "       -ops \"<options>\"\n"
    "                          Specify DR runtime options.  When specifying\n"
    "                          multiple options, enclose the entire list of\n"
    "                          options in quotes, or repeat the -ops.\n"
    "                          Alternatively, if -c or -t is specified, the -ops\n"
    "                          may be omitted and DR options listed prior to -c,\n"
    "                          and -t, without quotes.\n"
    "       -attach <pid>\n"
    "                          Attach to the process with the given pid.\n"
    "       -process <pid> \n"
    "       -detach <pid>\n"
    "                          Detach dr from process with the given pid.\n"
    "       -logdir <dir>\n"
    "                          Logfiles will be stored in this directory.\n"
    "\n"
    "        -t <toolname> <options>\n"
    "                           Registers a pre-configured tool to run alongside DR.\n"
    "                           A tool is a client with a configuration file\n"
    "                           that sets the client options and path, providing a\n"
    "                           convenient launching command via this -t parameter.\n"
    "                           Available tools include: %s.\n"
    "                           All remaining arguments are interpreted as client\n"
    "                           options. Must come after all drrun and DR ops.\n"
    "                           Neither the path nor the options may contain semicolon\n"
    "                           characters or all 3 quote characters (\", \', `).\n"
    "\n"
    "        -c <path> <options>\n"
    "                           Registers one client to run alongside DR.  Assigns\n"
    "                           the client an id of 0.  All remaining arguments\n"
    "                           are interpreted as client options. Must come after \n"
    "                           all drrun and DR ops. Neither the path nor\n"
    "                           the options may contain semicolon characters or\n"
    "                           all 3 quote characters (\", \', `).\n";

static bool
does_file_exist(const char *path)
{
    bool ret = false;
    return (drfront_access(path, DRFRONT_EXIST, &ret) == DRFRONT_SUCCESS && ret);
}

static void
get_absolute_path(const char *src, char *buf, size_t buflen /*# elements*/)
{
    drfront_status_t sc = drfront_get_absolute_path(src, buf, buflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed (status=%d) to convert %s to an absolute path", sc, src);
}

/* Opens a filename and mode that are in utf8 */
static FILE *
fopen_utf8(const char *path, const char *mode)
{
    return fopen(path, mode);
}

static char tool_list[MAXIMUM_PATH];

static void
print_tool_list(FILE *stream)
{
    if (tool_list[0] != '\0')
        fprintf(stream, "       available tools include: %s\n", tool_list);
}

static void
read_tool_list(const char *dr_root)
{
    FILE *f;
    char list_file[MAXIMUM_PATH];
    size_t sofar = 0;
    const char *arch = IF_X64_ELSE("64", "32");
    _snprintf(list_file, BUFFER_SIZE_ELEMENTS(list_file), "%s/tools/list%s", dr_root,
              arch);
    NULL_TERMINATE_BUFFER(list_file);
    f = fopen_utf8(list_file, "r");
    if (f == NULL) {
        /* no visible error: we only expect to have a list for a package build */
        return;
    }
    while (fgets(tool_list + sofar,
                 (int)(BUFFER_SIZE_ELEMENTS(tool_list) - sofar - 1 /*space*/),
                 f) != NULL) {
        NULL_TERMINATE_BUFFER(tool_list);
        sofar += strlen(tool_list + sofar);
        tool_list[sofar - 1] = ','; /* replace newline with comma */
        /* add space */
        if (sofar < BUFFER_SIZE_ELEMENTS(tool_list))
            tool_list[sofar++] = ' ';
    }
    fclose(f);
    tool_list[sofar - 2] = '\0';
    NULL_TERMINATE_BUFFER(tool_list);
}

#define usage(list_ops, msg, ...)                                                \
    do {                                                                         \
        FILE *stream = (list_ops == true) ? stdout : stderr;                     \
        if ((msg)[0] != '\0')                                                    \
            fprintf(stderr, "ERROR: " msg "\n\n", ##__VA_ARGS__);                \
        fprintf(stream, "%s", usage_str);                                        \
        print_tool_list(stream);                                                 \
        if (list_ops) {                                                          \
            fprintf(stream, options_list_str, tool_list);                        \
            exit(0);                                                             \
        } else {                                                                 \
            fprintf(stream, "Run with -help to see " TOOLNAME " option list\n"); \
        }                                                                        \
        die();                                                                   \
    } while (0)

/* Unregister a process */
bool
unregister_proc(const char *process, pid_t pid)
{
    dr_config_status_t status = dr_unregister_process(process, pid, false, DR_PLATFORM_DEFAULT);
    if (status == DR_PROC_REG_INVALID) {
        error("no existing registration for %s", process == NULL ? "<null>" : process);
        return false;
    } else if (status == DR_FAILURE) {
        error("unregistration failed for %s", process == NULL ? "<null>" : process);
        return false;
    }
    return true;
}

/* Check if the provided root directory actually has the files we
 * expect.  Returns whether a fatal problem.
 */
static bool
check_dr_root(const char *dr_root, bool debug)
{
    char buf[MAXIMUM_PATH];
    const char *arch = IF_X64_ELSE("lib64", "lib32");
    const char *version = debug ? "debug" : "release";

    _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%s/%s/%s/libdynamorio.so", dr_root, arch, version);
    if (!does_file_exist(buf)) {
        error("cannot find required file %s\n", buf);
        return false;
    }
    return true;
}

/* Register a process to run under DR */
bool
register_proc(const char *process, pid_t pid, const char *dr_root, bool debug,
              const char *extra_ops)
{
    dr_config_status_t status;
    assert(dr_root != NULL);
    if (!does_file_exist(dr_root)) {
        error("cannot access DynamoRIO root directory %s", dr_root);
        return false;
    }

    if (!check_dr_root(dr_root, debug))
        return false;

    if (dr_process_is_registered(process, pid, false, DR_PLATFORM_DEFAULT, NULL, NULL, NULL,
                                 NULL)) {
        warn("overriding existing registration");
        if (!unregister_proc(process, pid))
            return false;
    }

    status = dr_register_process(process, pid, false, dr_root, DR_MODE_CODE_MANIPULATION, debug,
                                 DR_PLATFORM_DEFAULT, extra_ops);

    if (status != DR_SUCCESS) {
        /* USERPROFILE is not set by default over cygwin ssh */
        char buf[MAXIMUM_PATH];
            if (status == DR_CONFIG_DIR_NOT_FOUND) {
                dr_get_config_dir(false, true /*tmp*/, buf, BUFFER_SIZE_ELEMENTS(buf));
                error("process %s registration failed: check config dir %s permissions",
                      process == NULL ? "<null>" : process, buf);
            } else {
                error("process %s registration failed",
                      process == NULL ? "<null>" : process);
            }
        return false;
    }
    return true;
}

/* Check if the specified client library actually exists. */
void
check_client_lib(const char *client_lib)
{
    if (!does_file_exist(client_lib)) {
        warn("%s does not exist", client_lib);
    }
}

bool
register_client(const char *process_name, pid_t pid, client_id_t client_id,
                const char *path, const char *options)
{
    size_t priority;
    dr_config_status_t status;
    if (!dr_process_is_registered(process_name, pid, false, DR_PLATFORM_DEFAULT, NULL, NULL,
                                  NULL, NULL)) {
        error("can't register client: process %s is not registered",
              process_name == NULL ? "<null>" : process_name);
        return false;
    }

    check_client_lib(path);

    /* just append to the existing client list */
    priority = dr_num_registered_clients(process_name, pid, false, DR_PLATFORM_DEFAULT);

    info("registering client with id=%d path=|%s| ops=|%s|", client_id, path, options);
    dr_config_client_t info;
    info.struct_size = sizeof(info);
    info.id = client_id;
    info.priority = priority;
    info.path = (char *)path;
    info.options = (char *)options;
    info.is_alt_bitwidth = false;
    status = dr_register_client_ex(process_name, pid, false, DR_PLATFORM_DEFAULT, &info);
    if (status != DR_SUCCESS) {
        if (status == DR_CONFIG_STRING_TOO_LONG) {
            error("client %s registration failed: option string too long: \"%s\"", path,
                  options);
        } else if (status == DR_CONFIG_OPTIONS_INVALID) {
            error("client %s registration failed: options cannot contain ';' or all "
                  "3 quote types: %s",
                  path, options);
        } else {
            error("client %s registration failed with error code %d", path, status);
        }
        return false;
    }
    return true;
}

/* Appends a space-separated option string to buf.  A space is appended only if
 * the buffer is non-empty.  Aborts on buffer overflow.  Always null terminates
 * the string.
 * XXX: Use print_to_buffer.
 */
static void
add_extra_option(char *buf, size_t bufsz, size_t *sofar, const char *fmt, ...)
{
    ssize_t len;
    va_list ap;
    if (*sofar > 0 && *sofar < bufsz)
        buf[(*sofar)++] = ' '; /* Add a space. */

    va_start(ap, fmt);
    len = vsnprintf(buf + *sofar, bufsz - *sofar, fmt, ap);
    va_end(ap);

    if (len < 0 || (size_t)len >= bufsz) {
        error("option string too long, buffer overflow");
        die();
    }
    *sofar += len;
    /* be paranoid: though usually many calls in a row and could delay until end */
    buf[bufsz - 1] = '\0';
}

static bool
read_tool_file(const char *toolname, const char *dr_root, char *client,
               size_t client_size, char *ops, size_t ops_size, size_t *ops_sofar,
               char *tool_ops, size_t tool_ops_size, size_t *tool_ops_sofar)
{
    FILE *f;
    char config_file[MAXIMUM_PATH];
    char line[MAXIMUM_PATH];
    bool found_client = false;
    const char *arch = IF_X64_ELSE("64", "32");
    _snprintf(config_file, BUFFER_SIZE_ELEMENTS(config_file), "%s/tools/%s.drrun%s",
              dr_root, toolname, arch);
    NULL_TERMINATE_BUFFER(config_file);
    info("reading tool config file %s", config_file);

    f = fopen_utf8(config_file, "r");
    if (f == NULL) {
        error("cannot find tool config file %s", config_file);
        return false;
    }
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), f) != NULL) {
        ssize_t len;
        NULL_TERMINATE_BUFFER(line);
        len = strlen(line) - 1;
        while (len >= 0 && (line[len] == '\n' || line[len] == '\r')) {
            line[len] = '\0';
            len--;
        }
        if (line[0] == '#') {
            continue;
        } else if (strstr(line, "CLIENT_REL=") == line) {
            _snprintf(client, client_size, "%s/%s", dr_root,
                      line + strlen("CLIENT_REL="));
            client[client_size - 1] = '\0';
            found_client = true;
        } else if (strstr(line, IF_X64_ELSE("CLIENT64_REL=", "CLIENT32_REL=")) == line) {
            _snprintf(client, client_size, "%s/%s", dr_root,
                      line + strlen(IF_X64_ELSE("CLIENT64_REL=", "CLIENT32_REL=")));
            client[client_size - 1] = '\0';
            found_client = true;
        } else if (strstr(line, "CLIENT_ABS=") == line) {
            strncpy(client, line + strlen("CLIENT_ABS="), client_size);
            found_client = true;
        } else if (strstr(line, IF_X64_ELSE("CLIENT64_ABS=", "CLIENT32_ABS=")) == line) {
            strncpy(client, line + strlen(IF_X64_ELSE("CLIENT64_ABS=", "CLIENT32_ABS=")),
                    client_size);
            found_client = true;
        } else if (strstr(line, "DR_OP=") == line) {
            if (strcmp(line, "DR_OP=") != 0) {
                add_extra_option(ops, ops_size, ops_sofar, "\"%s\"",
                                 line + strlen("DR_OP="));
            }
        } else if (strstr(line, "TOOL_OP=") == line) {
            if (strcmp(line, "TOOL_OP=") != 0) {
                add_extra_option(tool_ops, tool_ops_size, tool_ops_sofar, "\"%s\"",
                                 line + strlen("TOOL_OP="));
            }
        } else if (strstr(line, "TOOL_OP_DR_PATH") == line) {
            add_extra_option(tool_ops, tool_ops_size, tool_ops_sofar, "\"%s\"", dr_root);
        } else if (strstr(line, "TOOL_OP_DR_BUNDLE=") == line) {
            if (strcmp(line, "TOOL_OP_DR_BUNDLE=") != 0) {
                add_extra_option(tool_ops, tool_ops_size, tool_ops_sofar, "%s `%s`",
                                 line + strlen("TOOL_OP_DR_BUNDLE="), ops);
            }
        } else if (strstr(line, "USER_NOTICE=") == line) {
            warn("%s", line + strlen("USER_NOTICE="));
        } else if (line[0] != '\0') {
            error("tool config file is malformed: unknown line %s", line);
            return false;
        }
    }
    fclose(f);
    return found_client;
}

int
main(int argc, char *targv[])
{
    char dr_root[MAXIMUM_PATH];
    char extra_ops[MAX_OPTIONS_STRING];
    size_t extra_ops_sofar = 0;

    bool has_client = false;
    char client_path[MAXIMUM_PATH];
    client_id_t client_id = 0;
    char client_ops[DR_MAX_OPTIONS_LENGTH];
    size_t client_sofar = 0;

    pid_t attach_pid = 0;
    pid_t real_pid = 0;
    pid_t detach_pid = 0;

    bool use_debug = false;
    int exitcode;

    char buf[MAXIMUM_PATH];
    char **argv;

    drfront_status_t sc;
    /* Convert to UTF-8 if necessary */
    sc = drfront_convert_args((const char **)targv, &argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to process args: %d", sc);

    extra_ops[0] = '\0';
    client_path[0]= '\0';
    client_ops[0] = '\0';

    /* default root: we assume this tool is in <root>/bin{32,64}/dr*.exe */
    get_absolute_path(argv[0], buf, BUFFER_SIZE_ELEMENTS(buf));
    NULL_TERMINATE_BUFFER(buf);
    char *c = buf + strlen(buf) - 1;
    while (*c != '\\' && *c != '/' && c > buf)
        c--;
    _snprintf(c + 1, BUFFER_SIZE_ELEMENTS(buf) - (c + 1 - buf), "..");
    NULL_TERMINATE_BUFFER(buf);
    get_absolute_path(buf, dr_root, BUFFER_SIZE_ELEMENTS(dr_root));
    NULL_TERMINATE_BUFFER(dr_root);
    info("default root: %s", dr_root);

    /* we re-read the tool list if the root or platform change */
    read_tool_list(dr_root);

    /* parse command line */
    for (int i = 1; i < argc; i++) {
        /* params with no arg */
        if (strcmp(argv[i], "-verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
            continue;
        } else if (strcmp(argv[i], "-quiet") == 0) {
            quiet = true;
            continue;
        } else if (strcmp(argv[i], "-debug") == 0) {
            use_debug = true;
            continue;
        } else if (!strcmp(argv[i], "-version")) {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
            printf(TOOLNAME " version %s -- build %d\n", STRINGIFY(VERSION_NUMBER),
                   BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
            printf(TOOLNAME " custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#else
            printf(TOOLNAME " custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
            exit(0);
        } else if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0 ||
                 strcmp(argv[i], "-h") == 0) {
            usage(true, "" /* no error msg */);
        } else {
            if (strcmp(argv[i], "-attach") != 0 && strcmp(argv[i], "-detach") != 0 &&
                strcmp(argv[i], "-process") != 0 &&
                strcmp(argv[i], "-logdir") != 0 && strcmp(argv[i], "-ops") != 0 &&
                strcmp(argv[i], "-c") != 0 && strcmp(argv[i], "-t") != 0) {
                usage(false, "invalid arguments %s", argv[i]);
            } else if (i == argc - 1) {
                usage(false, "too few arguments to %s", argv[i]);
            }
        }

        /* params with an arg */
        if (strcmp(argv[i], "-attach") == 0) {
            const char *pid_str = argv[++i];
            pid_t pid = strtoul(pid_str, NULL, 10);
            if (pid == ULONG_MAX)
                usage(false, "-attach expects an integer pid");
            if (pid <= 0)
                usage(false, "-attach expects an valid pid");
            attach_pid = pid;
            continue;
        } else if (strcmp(argv[i], "-process") == 0) {
            const char *pid_str = argv[++i];
            pid_t pid = strtoul(pid_str, NULL, 10);
            if (pid == ULONG_MAX)
                usage(false, "-process expects an integer pid");
            if (pid <= 0)
                usage(false, "-process expects an valid pid");
            real_pid = pid;
            continue;
        } else if (strcmp(argv[i], "-detach") == 0) {
            const char *pid_str = argv[++i];
            pid_t pid = strtoul(pid_str, NULL, 10);
            if (pid == ULONG_MAX)
                usage(false, "-detach expects an integer pid");
            if (pid <= 0)
                usage(false, "-detach expects an valid pid");
            detach_pid = pid;
            continue;
        } else if (strcmp(argv[i], "-logdir") == 0) {
            /* Accept this for compatibility with the old drrun shell script. */
            const char *dir = argv[++i];
            if (!does_file_exist(dir))
                usage(false, "-logdir %s does not exist", dir);
            add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops), &extra_ops_sofar,
                             "-logdir `%s`", dir);
            continue;
        } else if (strcmp(argv[i], "-ops") == 0) {
            /* support repeating the option (i#477) */
            add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops), &extra_ops_sofar,
                             "%s", argv[++i]);
            continue;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-t") == 0) {
            const char *client = argv[++i];    
            if (strcmp(argv[i - 1], "-t") == 0) {
                if (!read_tool_file(client, dr_root, client_path,
                                    BUFFER_SIZE_ELEMENTS(client_path), extra_ops,
                                    BUFFER_SIZE_ELEMENTS(extra_ops), &extra_ops_sofar,
                                    client_ops,
                                    BUFFER_SIZE_ELEMENTS(client_ops),
                                    &client_sofar))
                    usage(false, "unknown %s tool \"%s\" requested",
                            IF_X64_ELSE("64-bit", "32-bit/WOW64"), client);
            } else {
                _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), "%s",
                  client);
            }
            while (++i < argc) {
                add_extra_option(client_ops,
                                 BUFFER_SIZE_ELEMENTS(client_ops), &client_sofar,
                                 "\"%s\"", argv[i]);
            }
            has_client = true;
        }
    }
    if(attach_pid == 0 && detach_pid == 0) {
        usage(false, "must use -attach <pid> or -detach <pid>");
    }
    if(detach_pid != 0) {
        drcct_detach_inject_ptrace(detach_pid, verbose);
        goto cleanup;
    }
    if (real_pid == 0) {
        real_pid = attach_pid;
    }
    char exe_str[MAXIMUM_PATH];
    sprintf(exe_str, "/proc/%u/exe", attach_pid);
    ssize_t size = readlink(exe_str, buf, BUFFER_SIZE_ELEMENTS(buf));
    if (size > 0) {
        if (size < BUFFER_SIZE_ELEMENTS(buf))
            buf[size] = '\0';
        else
            NULL_TERMINATE_BUFFER(buf);
    }
    char* app_name = strdup(buf);

    /* support running out of a debug build dir */
    if (!use_debug &&
        !check_dr_root(dr_root, false) &&
        check_dr_root(dr_root, true)) {
        info("debug build directory detected: switching to debug build");
        use_debug = true;
    }

    dr_get_config_dir(false, true /*use temp*/, buf, BUFFER_SIZE_ELEMENTS(buf));
    info("configuration directory is \"%s\"", buf);

    char* process = strrchr(app_name, '/');
    if(real_pid != attach_pid) {
        if (!register_proc(process, real_pid, dr_root, use_debug, extra_ops))
            goto error;
        if (has_client) {
            if (!register_client(process, real_pid, client_id, client_path, client_ops))
                goto error;
        }
    }
    
    if (!register_proc(process, attach_pid, dr_root, use_debug, extra_ops))
        goto error;
    if (has_client) {
        if (!register_client(process, attach_pid, client_id, client_path, client_ops))
            goto error;
    }

    drcct_attach_inject_ptrace(attach_pid, process, verbose);
    goto cleanup;
error:
    exitcode = 1;
cleanup:
    sc = drfront_cleanup_args(argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to free memory for args: %d", sc);
    return exitcode;
}
