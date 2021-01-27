/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _GO_FUNCS_H_
#define _GO_FUNCS_H_

#include <string>
#include "cgo_defines.h"

go_type_name_t
cgo_get_type_name(go_type_t * go_type, go_moduledata_t* go_firstmoduledata);

std::string
cgo_get_type_name_string(go_type_t * go_type, go_moduledata_t* go_firstmoduledata);


#endif // _GO_FUNCS_H_