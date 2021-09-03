#include <stdio.h>
#include <stdlib.h>
#include <omp.h>

#define N 1000000


static int array[N];
int main()
{
  int *p = (int *) malloc (N * sizeof(int));
  int i;
  
#pragma omp parallel for
  for (i = 0; i<N; i++) {
    array[i] += p [i] + 1;
  }

  return 0;
}
