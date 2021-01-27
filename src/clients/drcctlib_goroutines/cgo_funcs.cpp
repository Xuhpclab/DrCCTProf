/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstdint>
#include "cgo_funcs.h"

go_type_name_t
cgo_get_type_name(go_type_t * go_type, go_moduledata_t* go_firstmoduledata){
    go_type_name_t result = {NULL};
    if (go_type->str == 0 || go_type->str == -1) {
        return result;
    }
    for(go_moduledata_t* temp = go_firstmoduledata; temp != NULL; temp =  temp->next) {
        if ((uint64_t)go_type >= (uint64_t)temp->types && (uint64_t)go_type < (uint64_t)temp->etypes) {
            result.data = (uint8_t*)((uint64_t)temp->types + (uint64_t)go_type->str);
            if((uint64_t)result.data >= (uint64_t)temp->etypes) {
                result.data = NULL;
            }
            break;
        }
    }
    return result;
}

std::string
cgo_get_type_name_string(go_type_t * go_type, go_moduledata_t* go_firstmoduledata) {
    go_type_name_t go_type_name = cgo_get_type_name(go_type, go_firstmoduledata);
    if(go_type_name.data == NULL) {
        return "";
    }
    int len = ((uint16_t)go_type_name.data[1] << 8) + (uint16_t)go_type_name.data[2];
    char* data = (char*)(go_type_name.data + 3);
    if((go_type->tflag & 0x02) != 0) {
        data = (char*)(go_type_name.data + 4);;
    }
    std::string result(data, len);
    return result;
}