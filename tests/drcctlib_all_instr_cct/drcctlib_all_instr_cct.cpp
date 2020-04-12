#include <iostream>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <unistd.h>
#include <vector>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                           \
    do {                                                                           \
        char name[MAXIMUM_PATH] = "";                                              \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));             \
        pid_t pid = getpid();                                                      \
        dr_printf("[(%s%d)drcctlib_all_instr_cct msg]====" format "\n", name, pid, \
                  ##args);                                                         \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    do {                                                                                 \
        char name[MAXIMUM_PATH] = "";                                                    \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                   \
        pid_t pid = getpid();                                                            \
        dr_printf("[(%s%d)drcctlib_all_instr_cct(%s%d) msg]====" format "\n", name, pid, \
                  ##args);                                                               \
    } while (0);                                                                         \
    dr_exit_process(-1)

static void
ClientInit(int argc, const char *argv[])
{

}

static void
ClientExit(void)
{
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_all_instr_cct'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL, NULL, NULL, DRCCTLIB_DEFAULT);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif