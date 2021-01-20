/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "drcctlib_utils.h"

uint64_t
hexadecimal_char_to_uint64(char* hex, int size)
{
    uint64_t result = 0;
    uint64_t pow_result = 1;
    for(int i = size - 1; i >= 0; i--) {
        int temp = 0;
        if(hex[i] <= '9' && hex[i] >= '0') {
            temp = hex[i] - '0';
        }
        if (hex[i] <= 'f' && hex[i] >= 'a') {
            temp = hex[i] - 'a' + 10;
        }
        result += pow_result * temp;
        pow_result *= 16;
    }
    return result;
}