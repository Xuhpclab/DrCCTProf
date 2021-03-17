/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstdint>
#include "cgo_funcs.h"
// #include "dr_api.h"


std::string
cgo_go_name_to_string(go_name_t* go_name)
{
    if(go_name->byte == NULL) {
        return "";
    }
    int len = ((uint16_t)go_name->byte[1] << 8) + (uint16_t)go_name->byte[2];
    char* data = (char*)(go_name->byte + 3);
    std::string result(data, len);
    return result;
}

bool
cgo_type_kind_is(go_type_t * go_type, go_kind_t match_kind)
{
    // dr_printf("go_type->kind(%p) (%p) (%p) (%d)\n", go_type->kind, go_kind_t::kindMask, match_kind, (go_type->kind & go_kind_t::kindMask) == match_kind);
    return (go_type->kind & go_kind_t::kindMask) == match_kind;
}

std::string
cgo_get_struct_pkg_path(go_struct_type_t *type)
{
    return cgo_go_name_to_string(&(type->pkgPath));
}

int64_t
cgo_get_struct_fields_length(go_struct_type_t *type)
{
    return type->fields.len;
}

go_struct_field_t*
cgo_get_struct_field(go_struct_type_t *type, int64_t index)
{
    if(index >= type->fields.len) {
        return NULL;
    }
    go_struct_field_t* cache = (go_struct_field_t*)(type->fields.data);
    return cache + index;
}

go_type_t *
cgo_get_struct_field_type(go_struct_type_t *type, int64_t index)
{
    go_struct_field_t* field = cgo_get_struct_field(type, index);
    if(!field) {
        return NULL;
    }
    return field->typ;
}


go_name_t
cgo_get_type_name(go_type_t * go_type, go_moduledata_t* go_firstmoduledata){
    go_name_t result = {NULL};
    if (go_type->str == 0 || go_type->str == -1) {
        return result;
    }
    for(go_moduledata_t* temp = go_firstmoduledata; temp != NULL; temp =  temp->next) {
        if ((uint64_t)go_type >= (uint64_t)temp->types && (uint64_t)go_type < (uint64_t)temp->etypes) {
            result.byte = (uint8_t*)((uint64_t)temp->types + (uint64_t)go_type->str);
            if((uint64_t)result.byte >= (uint64_t)temp->etypes) {
                result.byte = NULL;
            }
            break;
        }
    }
    return result;
}

std::string
cgo_get_type_name_string(go_type_t * go_type, go_moduledata_t* go_firstmoduledata) {
    go_name_t go_type_name = cgo_get_type_name(go_type, go_firstmoduledata);
    if(!go_type_name.byte) {
        return cgo_go_name_to_string(&go_type_name);
    }
    std::string result = cgo_go_name_to_string(&go_type_name);
    if((go_type->tflag & 0x02) != 0){
        result = result.substr(1);
    }
    return result;
}

