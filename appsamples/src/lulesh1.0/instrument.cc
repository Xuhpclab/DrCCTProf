#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <math.h>

#ifdef POLYBENCH_PAPI
# include <papi.h>
# define POLYBENCH_MAX_NB_PAPI_COUNTERS 96
  const unsigned int polybench_papi_eventlist[] = {
#include "papi_counters.list"    
    0
  };
  int polybench_papi_eventset;
  long_long polybench_papi_values[POLYBENCH_MAX_NB_PAPI_COUNTERS];

#endif


#ifndef POLYBENCH_CACHE_SIZE_KB
# define POLYBENCH_CACHE_SIZE_KB 8192
#endif

/* Timer code (gettimeofday). */
double polybench_t_start, polybench_t_end;

static
inline
double rtclock()
{
    struct timezone Tzp;
    struct timeval Tp;
    int stat;
    stat = gettimeofday (&Tp, &Tzp);
    if (stat != 0)
      printf("Error return from gettimeofday: %d", stat);
    return (Tp.tv_sec + Tp.tv_usec * 1.0e-6);
}

inline
void polybench_flush_cache()
{
  int cs = POLYBENCH_CACHE_SIZE_KB * 1024 / sizeof(double);
  double* flush = (double*) calloc(cs, sizeof(double));
  int i;
  double tmp = 0.0;
  #pragma omp parallel for
  for (i = 0; i < cs; i++)
    tmp += flush[i];
  assert (tmp <= 10.0);
}

#ifdef POLYBENCH_LINUX_FIFO_SCHEDULER
inline
void polybench_linux_fifo_scheduler()
{
  /* Use FIFO scheduler to limit OS interference. Program must be run
     as root, and this works only for Linux kernels. */
  struct sched_param schedParam;
  schedParam.sched_priority = sched_get_priority_max(SCHED_FIFO);
  sched_setscheduler(0, SCHED_FIFO, &schedParam);
}


inline
void polybench_linux_standard_scheduler()
{
  /* Restore to standard scheduler policy. */
  struct sched_param schedParam;
  schedParam.sched_priority = sched_get_priority_max(SCHED_OTHER);
  sched_setscheduler(0, SCHED_OTHER, &schedParam);
}
#endif

#ifdef POLYBENCH_PAPI

void test_fail(char *file, int line, char *call, int retval)
{
   char buf[128];

   memset(buf, '\0', sizeof(buf));
   if (retval != 0)
      fprintf(stdout,"%-40s FAILED\nLine # %d\n", file, line);
   else {
      fprintf(stdout,"%-40s SKIPPED\n", file);
      fprintf(stdout,"Line # %d\n", line);
   }
   if (retval == PAPI_ESYS) {
      sprintf(buf, "System error in %s", call);
      perror(buf);
   } else if (retval > 0) {
      fprintf(stdout,"Error: %s\n", call);
   } else if (retval == 0) {
      fprintf(stdout,"Error: %s\n", call);
   } else {
      char errstring[PAPI_MAX_STR_LEN];
      PAPI_perror(retval, errstring, PAPI_MAX_STR_LEN);
      fprintf(stdout,"Error in %s: %s\n", call, errstring);
   }
   fprintf(stdout,"\n");
   if ( PAPI_is_initialized() ) PAPI_shutdown();
   exit(1);
}


inline
void polybench_papi_init()
{
  int retval;
  polybench_papi_eventset = PAPI_NULL;

  if ((retval = PAPI_library_init(PAPI_VER_CURRENT)) != PAPI_VER_CURRENT)
    test_fail(__FILE__, __LINE__, "PAPI_library_init", retval);

  if ((retval = PAPI_create_eventset(&polybench_papi_eventset)) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_create_eventset", retval);
}


inline
void polybench_papi_close()
{
  int retval;
  if ((retval = PAPI_destroy_eventset(&polybench_papi_eventset)) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_destroy_eventset", retval);
  if (PAPI_is_initialized())
    PAPI_shutdown();
}

inline
int polybench_papi_start_counter(int evid)
{
# ifndef POLYBENCH_NO_FLUSH_CACHE
  polybench_flush_cache();
# endif
  int retval = 1;
  char descr[PAPI_MAX_STR_LEN];
  PAPI_event_info_t evinfo;
  PAPI_event_code_to_name(polybench_papi_eventlist[evid], descr);
  if (PAPI_add_event(polybench_papi_eventset,
		     polybench_papi_eventlist[evid]) != PAPI_OK)
    return 1;

  if (PAPI_get_event_info(polybench_papi_eventlist[evid], &evinfo) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_get_event_info", retval);


  if ((retval = PAPI_start(polybench_papi_eventset)) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_start", retval);

  return 0;
}


inline
void polybench_papi_stop_counter(int evid)
{
  int retval;
  long_long values[1];
  values[0] = 0;
  if ((retval = PAPI_read(polybench_papi_eventset, &values[0])) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_read", retval);

  if ((retval = PAPI_stop(polybench_papi_eventset, NULL)) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_stop", retval);

  polybench_papi_values[evid] = values[0];

  if ((retval = PAPI_remove_event(polybench_papi_eventset,
				  polybench_papi_eventlist[evid])) != PAPI_OK)
    test_fail(__FILE__, __LINE__, "PAPI_remove_event", retval);
}


inline
void polybench_papi_print()
{
  int evid;
  for (evid = 0; polybench_papi_eventlist[evid] != 0; ++evid)
    printf ("%llu ", polybench_papi_values[evid]);
  printf ("\n");

}

#endif // ! POLYBENCH_PAPI


inline
void polybench_prepare_instruments()
{
#ifndef POLYBENCH_NO_FLUSH_CACHE
  polybench_flush_cache();
#endif
#ifdef POLYBENCH_LINUX_FIFO_SCHEDULER
  polybench_linux_fifo_scheduler();
#endif
}


//inline
void polybench_timer_start()
{
  polybench_prepare_instruments();
  polybench_t_start = rtclock();
}


//inline
void polybench_timer_stop()
{
  polybench_t_end = rtclock();
#ifdef POLYBENCH_LINUX_FIFO_SCHEDULER
  polybench_linux_standard_scheduler();
#endif
}


//inline
void polybench_timer_print()
{
  printf("Polybench timer instrumentation ... ");
  printf ("%0.6lf (secs)\n", polybench_t_end - polybench_t_start);
}
