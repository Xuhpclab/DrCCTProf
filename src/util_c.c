#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util_c.h"

/**
 * Remove leading whitespace characters from string
 */
static void 
ltrim(char * str)
{
    size_t index = 0;
    while(str[index] == ' ' || str[index] == '\t' || str[index] == '\n')
    {
        index ++;
    }
    if(index > 0)
    {
        size_t new_len = strlen(str) - index;
        for(size_t i = 0; i < new_len; i++) {
            str[i] = str[i + index];
        }
        str[new_len] = '\0';
    }
}

/**
 * Remove end whitespace characters from string
 */
static void 
rtrim(char * str)
{
    int index = strlen(str) - 1;
    while(index >= 0 && 
        (str[index] == ' ' || str[index] == '\t' || str[index] == '\n'))
    {
        str[index] = '\0';
        index --;
    }
}

static inline char* 
trim(char * str)
{
    ltrim(str);
    rtrim(str);
    return str;
}

char* 
get_cpu_info(char * key) {
    char* value = NULL;
    char cache[1000];
    sprintf(cache, "lscpu | grep \"%s\" > temp.log", key);
    system(cache);
    
    FILE *fp = fopen("temp.log", "r");
    if(NULL == fp) {
        printf("failed to open temp.log\n");
    } else {
        fgets(cache, sizeof(cache), fp);
        strtok(cache, ":");
        value = trim(strtok(NULL, ":"));
        printf("value: %s\n", value);
        fclose(fp);
    }

    system("rm temp.log");
    return value;
}

#ifdef DRCCT_PROF_UTIL_TEST
void main()
{
    printf("=== cpu Vendor ID ===\n");
    get_cpu_info("Vendor ID");
    printf("=== cpu Model name ===\n");
    get_cpu_info("Model name");
}
#endif