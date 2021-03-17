/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _ELF_UTILS_H_
#define _ELF_UTILS_H_

#include "libelf.h"

// compute static variables
#ifdef X64
#    define elf_getshdr elf64_getshdr
#    define Elf_Shdr Elf64_Shdr
#    define Elf_Sym Elf64_Sym
#    define ELF_ST_TYPE ELF64_ST_TYPE
#else
#    define elf_getshdr elf32_getshdr
#    define Elf_Shdr Elf32_Shdr
#    define Elf_Sym Elf32_Sym
#    define ELF_ST_TYPE ELF32_ST_TYPE
#endif

Elf_Scn *
find_elf_section_by_name(Elf *elf, const char *match_name);

#endif // _ELF_UTILS_H_