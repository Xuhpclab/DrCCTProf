/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include <cstdint>
#include <string.h>
#include "elf_utils.h"

Elf_Scn *
find_elf_section_by_name(Elf *elf, const char *match_name)
{
    Elf_Scn *scn;
    size_t shstrndx; /* Means "section header string table section index" */

    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        return NULL;
    }

    for (scn = elf_getscn(elf, 0); scn != NULL; scn = elf_nextscn(elf, scn)) {
        Elf_Shdr *section_header = elf_getshdr(scn);
        const char *sec_name;
        if (section_header == NULL) {
            continue;
        }
        sec_name = elf_strptr(elf, shstrndx, section_header->sh_name);
        if (strcmp(sec_name, match_name) == 0) {
            if (section_header->sh_type == SHT_NOBITS)
                return NULL;
            return scn;
        }
    }
    return NULL;
}