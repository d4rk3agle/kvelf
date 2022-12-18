#ifndef PARSE_H
#define PARSE_H

#include "types.h"

/* Parse ELF header */
void parse_elf_header(FILE *fp, u32 elfHeaderOffset);

/* Parse ELF sections */
void parse_elf_sections(FILE * fp ,u32 sectionOffset, u32 numOfSections, u8 sectionNamesIdx, u8 elfClass);

/* Parse ELF segments */
void parse_elf_segments(FILE * fp ,u32 segmentOffset, u32 numOfSegments, u8 elfClass);

/* Parse ELF symbols */
void parse_elf_symbols(FILE * fp , u32 symbolTableOffset , u8 elfClass);

/* Parse ELF relocations */
void parse_elf_relocs(FILE * fp, u8 elfClass);

/* This function simply dumps the given number of raw bytes */
void pe_parse_raw_bytes(FILE *fp, u64 rawBytesOffset, u32 nofRawBytes);

/* Parse an ELF section */
void parse_elf_section(FILE *fp, u32 sectionsOffset, u32 sectionIdx, u8 elfClass);

#endif
