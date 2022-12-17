
#include "./types.h"
#include "./elf.h"


/* Get string representation of the ELF ABI */
u8 * get_elf_abi_string(u8 elfAbi){

     if (elfAbi==ELFOSABI_NONE || elfAbi==ELFOSABI_SYSV)
        return "System V";
    else if (elfAbi==ELFOSABI_HPUX)
        return "HP-UX";
    else if (elfAbi==ELFOSABI_NETBSD)
        return "NetBSD";
    else if (elfAbi==ELFOSABI_GNU || elfAbi==ELFOSABI_LINUX)
        return "GNU";
    else if (elfAbi==ELFOSABI_SOLARIS)
        return "Solaris";
    else if (elfAbi==ELFOSABI_AIX)
        return "AIX";
    else if (elfAbi==ELFOSABI_IRIX)
        return "IRIX";
    else if (elfAbi==ELFOSABI_FREEBSD)
        return "FreeBSD";
    else if (elfAbi==ELFOSABI_TRU64)
        return "TRU64";
    else if (elfAbi==ELFOSABI_MODESTO)
        return "Modesto";
    else if (elfAbi==ELFOSABI_OPENBSD)
        return "OpenBSD";
    else if (elfAbi==ELFOSABI_ARM_AEABI)
        return "ARB_EABI";
    else if (elfAbi==ELFOSABI_ARM)
        return "ARM";
    else if (elfAbi==ELFOSABI_STANDALONE)
        return "Standalone";
    return "N/A";

}




/* Get string representation of the ELF class */
u8 * get_elf_class_string(u8 elfClass){
	if(elfClass==ELFCLASS32)
		return "32bit";
	if(elfClass==ELFCLASS64)
		return "64bit";
	if(elfClass==ELFCLASSNONE)
		return "?";
	
	return "N/A";

}

/* Get string representation of the ELF data encoding */
u8 * get_elf_dataencoding_string(u8 dataEncoding){
	if(dataEncoding==ELFDATANONE)
		return "Inv";
	if(dataEncoding==ELFDATA2LSB)
		return "2'c Little-Indian";
	if(dataEncoding==ELFDATA2MSB)
		return "2'c Big-Indian";

	return "N/A";

}


/* Get string representation of the ELF file type */
u8 * get_elf_object_file_type(u16 type){
	if(type==ET_NONE)
		return "No type";
	if(type==ET_REL)
		return "Reloc";
	if(type==ET_EXEC)
		return "Exec";
	if(type==ET_DYN)
		return "Dyn";
	if(type==ET_CORE)
		return "Core";

	return "N/A";

}

/* Get string representation of the ELF machine */
u8 * get_elf_machine(u16 machine){

	if(machine==EM_386)
		return "Intel 80386";
	if(machine==EM_860)
		return "Intel 80860";
	if(machine==EM_IAMCU)
		return "Intel MCU";
	if(machine==EM_SPARC)
		return "UN SPARC";
	if(machine==EM_X86_64)
		return "x86-64";
    if(machine==EM_ARM)
        return "ARM";
	return "N/A";
}


/* Get string representation of the ELF section type */
u8 * get_elf_section_type(u32 sectionType){

    if (sectionType==SHT_NULL)
        return "NULL";
    if (sectionType==SHT_PROGBITS)
        return "PROGBITS";
    if (sectionType==SHT_SYMTAB)
        return "SYMTAB";
    if (sectionType==SHT_STRTAB)
        return "STRTAB";
    if (sectionType==SHT_REL)
        return "RELA";
    if (sectionType==SHT_HASH)
        return "HASH";
    if (sectionType==SHT_DYNAMIC)
        return "DYNAMIC";
    if (sectionType==SHT_NOTE)
        return "NOTE";
    if (sectionType==SHT_NOBITS)
        return "NO-BITS";
    if (sectionType==SHT_SHLIB)
        return "SHLIB";
    if (sectionType==SHT_DYNSYM)
        return "DYNSYM";
    if (sectionType==SHT_INIT_ARRAY)
        return "INIT_ARRAY";
    if (sectionType==SHT_FINI_ARRAY)
        return "FINI_ARRAY";
    if (sectionType==SHT_PREINIT_ARRAY)
        return "PREINIT_ARRAY";
    if (sectionType==SHT_GROUP)
        return "GROUP";
    if (sectionType==SHT_SYMTAB_SHNDX)
        return "SYMTAB_SHNDX";
    if (sectionType==SHT_NUM)
        return "NUM";
    if (sectionType==SHT_LOOS)
        return "LOOS";
    if (sectionType==SHT_GNU_ATTRIBUTES)
        return "GNU_ATTR";
    if (sectionType==SHT_GNU_HASH)
        return "GNU_HASH";
    if (sectionType==SHT_GNU_LIBLIST)
        return "GNU_LIBLIST";
    if (sectionType==SHT_CHECKSUM)
        return "CHECKSUM";
    if (sectionType==SHT_SUNW_move)
        return "SUN_MOVE";
    if (sectionType==SHT_SUNW_COMDAT)
        return "SUM_COMDAT";
    if (sectionType==SHT_SUNW_syminfo)
        return "SUN_SYMINFO";
    if (sectionType==SHT_GNU_verdef)
        return "GNU_VERDEF";
    if (sectionType==SHT_GNU_verneed)
        return "GNU_VERNEED";
    if (sectionType==SHT_GNU_versym)
        return "GNU_VERSYM";
    if (sectionType<= SHT_HIOS)
        return "OS_SPEC";
    if ((sectionType >= SHT_LOPROC) && (sectionType <= SHT_HIPROC) )
        return "PROC_SPEC";
    if ((sectionType >= SHT_LOUSER) && (sectionType <= 0x8fffffff) )
        return "APP_SPEC";
    
    return "UNKNOWN";

}


/* Get string representation of the ELF section flag */
void get_elf_section_flag(u32 sectionFlag, u8 * sectionFlags, u8 sectionFlagsBuffSize){

    // Zeroing out the buffer
    for(u8 i=0;i<sectionFlagsBuffSize;i++)
        sectionFlags[i]==0;

    u8 flagIndex=0;

    if (sectionFlag == SHF_MASKOS)
        sectionFlags[flagIndex]='O';
    else if (sectionFlag == SHF_MASKPROC)
        sectionFlags[flagIndex]='P';
    else {
        if (sectionFlag & SHF_ALLOC)
            sectionFlags[flagIndex++] = 'A';
        if (sectionFlag & SHF_WRITE)
            sectionFlags[flagIndex++] = 'W';
        if (sectionFlag & SHF_EXECINSTR)
            sectionFlags[flagIndex++] = 'X';
        if (sectionFlag & SHF_MERGE)
            sectionFlags[flagIndex++] = 'M';
        if (sectionFlag & SHF_STRINGS)
            sectionFlags[flagIndex++] = 'S';
        if (sectionFlag & SHF_INFO_LINK)
            sectionFlags[flagIndex++] = 'I';
        if (sectionFlag & SHF_LINK_ORDER)
            sectionFlags[flagIndex++] = 'L';
        if (sectionFlag & SHF_OS_NONCONFORMING)
            sectionFlags[flagIndex++] = 'N';
        if (sectionFlag & SHF_GROUP)
            sectionFlags[flagIndex++] = 'G';
        if (sectionFlag & SHF_TLS)
            sectionFlags[flagIndex++] = 'T';
        if (sectionFlag & SHF_COMPRESSED)
            sectionFlags[flagIndex++] = 'C';
        if (sectionFlag & SHF_EXCLUDE)
            sectionFlags[flagIndex++] = 'E';
        if (sectionFlag & SHF_ORDERED)
            sectionFlags[flagIndex++] = 'R';
    }

}

/* Get string representation of the ELF segment type */
u8 * get_elf_segment_type(u32 segmentType){


    if (segmentType== PT_NULL)
        return"NULL";
    else  if (segmentType== PT_LOAD)
        return"LOAD";
    else  if (segmentType== PT_DYNAMIC)
        return"DYN";
    else  if (segmentType== PT_INTERP)
        return"INTERP";
    else  if (segmentType== PT_NOTE)
        return"NOTE";
    else  if (segmentType== PT_SHLIB)
        return"SHLIB";
    else  if (segmentType== PT_PHDR)
        return"PHDR";
    else if (segmentType== PT_GNU_EH_FRAME)
        return"GNU-FRAME";
    else if (segmentType== PT_GNU_STACK)
        return"GNU-STACK";
    else if (segmentType== PT_GNU_RELRO)
        return"GNU-RELRO";
    else if (segmentType>= 0x70000000 && segmentType <=0x7fffffff)
        return"OS-SPEC";
    return "N/A";

}



/* Get string representation of the ELF segment flag */
void get_elf_segment_flag(u32 segmentFlag , u8 * segmentFlags , u8 segmentFlagsBuffSize){


    // Zeroing out the buffer
    for(u32 i=0;i<segmentFlagsBuffSize;i++)
        segmentFlags[i]=0;

    // String index to write flags
    u8 index=0;

    if (segmentFlag&PF_R)
        segmentFlags[index++]='R';
    if (segmentFlag & PF_W)
        segmentFlags[index++]='W';
    if (segmentFlag&PF_X)
        segmentFlags[index++]='X';

    // printf("%s\n",seg)

}
