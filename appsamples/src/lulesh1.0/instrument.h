/**
 * Polybench header for instrumentation.
 *
 * Programs must be compiled with `-I utilities utilities/instrument.c'
 *
 * Optionally, one can define:
 *
 * -DPOLYBENCH_TIME, to report the execution time,
 *   OR (exclusive):
 * -DPOLYBENCH_MFLOPS, to report the MFlop/s achieved
 *   OR (exclusive):
 * -DPOLYBENCH_PAPI, to use PAPI H/W counters (defined in instrument.c)
 *
 *
 * See README or utilities/instrument.c for additional options.
 *
 */
#define polybench_start_instruments
#define polybench_stop_instruments
#define polybench_print_instruments


/* PACE tile size selection support. */
extern void PACETileSizeVectorInit(int* tile_sizes, int dim, int scop_id);

/* PAPI support. */
#ifdef POLYBENCH_PAPI
extern const unsigned int polybench_papi_eventlist[];
# undef polybench_start_instruments
# undef polybench_stop_instruments
# undef polybench_print_instruments
# define polybench_start_instruments				\
  polybench_prepare_instruments();				\
  polybench_papi_init();					\
  int evid;							\
  for (evid = 0; polybench_papi_eventlist[evid] != 0; evid++)	\
    {								\
      if (polybench_papi_start_counter(evid))			\
	continue;						\

# define polybench_stop_instruments		\
      polybench_papi_stop_counter(evid);	\
    }						\
  polybench_papi_close();			\

# define polybench_print_instruments polybench_papi_print();
#endif


/* Timing support. */
#ifdef POLYBENCH_TIME
# undef polybench_start_instruments
# undef polybench_stop_instruments
# undef polybench_print_instruments
# define polybench_start_instruments polybench_timer_start();
# define polybench_stop_instruments polybench_timer_stop();
# define polybench_print_instruments polybench_timer_print();
#endif

/* Function declaration. */
#ifdef POLYBENCH_TIME
extern void polybench_timer_start();
extern void polybench_timer_stop();
extern void polybench_timer_print();
#endif

#ifdef POLYBENCH_PAPI
extern void polybench_prepare_instruments();
extern int polybench_papi_start_counter(int evid);
extern void polybench_papi_stop_counter(int evid);
extern void polybench_papi_init();
extern void polybench_papi_close();
extern void polybench_papi_print();
#endif
