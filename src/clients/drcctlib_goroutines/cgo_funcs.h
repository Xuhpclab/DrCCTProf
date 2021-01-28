/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _GO_FUNCS_H_
#define _GO_FUNCS_H_

#include <string>
#include "cgo_defines.h"

std::string
cgo_go_name_to_string(go_name_t* go_name);

bool
cgo_type_kind_is(go_type_t * go_type, go_kind_t match_kind);

// go_struct_type_t
std::string
cgo_get_struct_pkg_path(go_struct_type_t *type);

int64_t
cgo_get_struct_fields_length(go_struct_type_t *type);

go_struct_field_t*
cgo_get_struct_field(go_struct_type_t *type, int64_t index);

go_type_t *
cgo_get_struct_field_type(go_struct_type_t *type, int64_t index);



go_name_t
cgo_get_type_name(go_type_t * go_type, go_moduledata_t* go_firstmoduledata);

std::string
cgo_get_type_name_string(go_type_t * go_type, go_moduledata_t* go_firstmoduledata);


#endif // _GO_FUNCS_H_