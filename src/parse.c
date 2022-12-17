#include <stdio.h>
#include <stdlib.h>
#include "types.h"
#include "./debug.h"
#include "./elf.h"
#include "./error.h"

/* Parse ELF header */
void parse_elf_header(FILE *fp, u32 elfHeaderOffset){

	fseek(fp,elfHeaderOffset,SEEK_SET);

	// Reading ELF header's 16 byte metadata
	u8 elfHeaderFirst16Bytes[16];
	if(fread(elfHeaderFirst16Bytes,1,16,fp)!=16){
		debug("Cannot read ELF header 16 byte metadata\n",DEBUG_STATUS_ERROR);
		exit(ERROR_CANNOT_READ_FILE);
	}

    printf("\n");
    display("Class: ",DISPLAY_COLOR_ORANGE);
    printf("%s\n",get_elf_class_string(elfHeaderFirst16Bytes[EI_CLASS]));
    
    display("Encoding: ",DISPLAY_COLOR_ORANGE);
    printf("%s\n",get_elf_dataencoding_string(elfHeaderFirst16Bytes[EI_DATA]));
    
    display("ABI: ",DISPLAY_COLOR_ORANGE);
    printf("%s\n",get_elf_abi_string(elfHeaderFirst16Bytes[EI_OSABI]));
    
    display("ABI Ver: ",DISPLAY_COLOR_ORANGE);
    printf("ABI Ver: %d\n",elfHeaderFirst16Bytes[EI_ABIVERSION]);


    fseek(fp,elfHeaderOffset,SEEK_SET);

    // Processing the whole header
    u8 elfClass, elfType, elfMachine;

    if (elfHeaderFirst16Bytes[EI_CLASS] == ELFCLASS32){
        // // 32-bit class
        Elf32_Ehdr fileElf32H;

        if ( fread(&fileElf32H,1,sizeof(Elf32_Ehdr),fp) != sizeof(Elf32_Ehdr))
            debug("Cannot read the ELF header from the file\n",DEBUG_STATUS_ERROR);

        else{

            display("Type: ",DISPLAY_COLOR_ORANGE);
            printf("%s\n",get_elf_object_file_type(fileElf32H.e_type));
            
            display("Machine: ",DISPLAY_COLOR_ORANGE);
            printf("%s\n",get_elf_machine(fileElf32H.e_machine));
           
            display("Entry: ",DISPLAY_COLOR_ORANGE);
            printf("0x%016x\n",fileElf32H.e_entry);

            // Processing the sections
            if (fileElf32H.e_shnum) {
                display("Sections Table Address: ",DISPLAY_COLOR_ORANGE);
                printf("0x%016x\n", fileElf32H.e_shoff);
                
                display("Sections: ",DISPLAY_COLOR_ORANGE);
                printf("%d of %d bytes\n", fileElf32H.e_shnum, fileElf32H.e_shentsize);
                
                display("Sections' names table entry index: ",DISPLAY_COLOR_ORANGE);
                printf("%d\n",fileElf32H.e_shstrndx);
            } else{
                display("Sections: ",DISPLAY_COLOR_ORANGE);
                printf("0\n");
            }
            
            // Processing the segments
            if (fileElf32H.e_phnum) {
                display("Segments Table Address: ",DISPLAY_COLOR_ORANGE);
                printf("0x%016x\n", fileElf32H.e_phoff);

                display("Segments: ",DISPLAY_COLOR_ORANGE);
                printf("%d of %d bytes \n", fileElf32H.e_phnum, fileElf32H.e_phentsize);
            } else{
                display("Segments: ",DISPLAY_COLOR_ORANGE);
                printf("0\n");
            }
        }
    }   else if (elfHeaderFirst16Bytes[EI_CLASS] == ELFCLASS64) {
        
        Elf64_Ehdr fileElf64H;

        if ( fread(&fileElf64H,1,sizeof(Elf64_Ehdr),fp) != sizeof(Elf64_Ehdr))
            debug("Cannot read the ELF header from the file\n",DEBUG_STATUS_ERROR);
        else{

            display("Type: ",DISPLAY_COLOR_ORANGE);
            printf("%s\n",get_elf_object_file_type(fileElf64H.e_type));
           
            display("Machine: ",DISPLAY_COLOR_ORANGE);     
            printf("%s\n",get_elf_machine(fileElf64H.e_machine));
           
            display("Entry: ",DISPLAY_COLOR_ORANGE);
            printf("0x%016x\n",fileElf64H.e_entry);

            // Processing the sections
            if (fileElf64H.e_shnum) {
                display("Sections Table Address: ",DISPLAY_COLOR_ORANGE);
                printf("0x%016x\n", fileElf64H.e_shoff);
                
                display("Sections: ",DISPLAY_COLOR_ORANGE);
                printf("%d of %d bytes\n", fileElf64H.e_shnum, fileElf64H.e_shentsize);
                          
                display("Sections' names table entry index: ",DISPLAY_COLOR_ORANGE);
                printf("%d\n",fileElf64H.e_shstrndx);
           
            } else{
                display("Sections: ",DISPLAY_COLOR_ORANGE);  
                printf("0\n");
            }

            // Processing the segments
            if (fileElf64H.e_phnum) {
                display("Segments Table Address: ",DISPLAY_COLOR_ORANGE);
                printf("0x%016x\n", fileElf64H.e_phoff);
                
                display("Segments: ",DISPLAY_COLOR_ORANGE);
                printf("%d of %d bytes \n", fileElf64H.e_phnum, fileElf64H.e_phentsize);
            } else{
                display("Segments: ",DISPLAY_COLOR_ORANGE);

                printf("0\n");
            }
        }
    }

    display("File Version: ",DISPLAY_COLOR_ORANGE);
    printf("%d\n",elfHeaderFirst16Bytes[EI_VERSION]);
    printf("\n");

}

/* Parse ELF sections */
void parse_elf_sections(FILE * fp ,u32 sectionsOffset, u32 numOfSections, u8 sectionNamesIdx, u8 elfClass){

    printf("Flags: \n");
    printf("(A)[Alloc] (W)[Write] (X)[Exec] (M)[Merge] (S)[Strings]\n");
    printf("(I)[Info Link] (L)[Link Order] (N)[OS-Nonconforming] (G)[Group] (T)[TLS]\n");
    printf("(C)[Compressed] (E)[Excluded] (R)[Required Special Ordering]\n");
    printf("(O)[OS-MASK] (P)[Processor-MASK]\n");
    printf("-------------------------------------------------------------\n");

    if(!sectionsOffset)
    	debug("No sections in this file\n",DEBUG_STATUS_INF);
    else{

        // Seeking to the start of the sections table
        fseek(fp,sectionsOffset,SEEK_SET);

	    if (elfClass == ELFCLASS32){

            // Seeking to the section containing sections' names
            fseek(fp,sectionsOffset + sectionNamesIdx * sizeof(Elf32_Shdr),SEEK_SET);
            
            // Reading the section header string table entry
            Elf32_Shdr elf32Shdr;
            fread(&elf32Shdr,1,sizeof(Elf32_Shdr),fp);
            u8 * shStrings = malloc(elf32Shdr.sh_size);

            if (!shStrings)
                debug("Cannot allocate memory for header names\n",DEBUG_STATUS_ERROR);
            else{

                // Seek to the section header strings by using the offset of the entry
                fseek(fp,elf32Shdr.sh_offset ,SEEK_SET);

                // Reading the strings into the buffer allocated for the names
                fread(shStrings,1,elf32Shdr.sh_size ,fp);

                // Seeking to the start of the section header table for parsing all the sections
                fseek(fp,sectionsOffset,SEEK_SET);

                // Allocating memory for section's flag
                u8 sectionFlags[16];

                for ( u32 i=0;i<numOfSections;i++){

                    if(fread(&elf32Shdr,1,sizeof(Elf32_Shdr),fp)!=sizeof(Elf32_Shdr))
                        debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
                    else{
                        printf("(%d)-------%s--------\n",i,shStrings + elf32Shdr.sh_name);
                        display("    Type:  ",DISPLAY_COLOR_ORANGE);  
                        printf("%s\n",get_elf_section_type(elf32Shdr.sh_type));

                        get_elf_section_flag(elf32Shdr.sh_flags,sectionFlags,16);
                        
                        display("    Flags:  ",DISPLAY_COLOR_ORANGE);
                        printf("%s\n",sectionFlags);
                        
                        display("    Address:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%016x\n",elf32Shdr.sh_addr);
                        
                        display("    Offset:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf32Shdr.sh_offset);

                        display("    Size:  ",DISPLAY_COLOR_ORANGE);
                        printf("    Size:  %d(B)\n",elf32Shdr.sh_size);
                        
                        display("    Align:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf32Shdr.sh_addralign);
                        
                        display("    Link:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf32Shdr.sh_link);
                        
                        display("    Info:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf32Shdr.sh_info);
                        
                        display("    EntSize:  ",DISPLAY_COLOR_ORANGE);
                        printf("%d(B)\n",elf32Shdr.sh_entsize);
                    }
                }
                // Freeing the allocated memory for the section's names
                free(shStrings);
            }
	   }
	    
	    else if (elfClass == ELFCLASS64){

            // Seeking to the section containing sections' names
            fseek(fp, sectionsOffset + sectionNamesIdx * sizeof(Elf64_Shdr),SEEK_SET);
            
            // Reading the section header string table entry
            Elf64_Shdr elf64Shdr;
            fread(&elf64Shdr,1,sizeof(elf64Shdr),fp);
            u8 * shStrings = malloc(elf64Shdr.sh_size);

            if (!shStrings)
                debug("Cannot allocate memory for header names\n",DEBUG_STATUS_ERROR);
            else{

                // Seek to the section header strings by using the offset of the entry
                fseek(fp,elf64Shdr.sh_offset ,SEEK_SET);

                // Reading the strings into the buffer allocated for the names
                fread(shStrings,1,elf64Shdr.sh_size ,fp);

                // Seeking to the start of the section header table for parsing all the sections
                fseek(fp,sectionsOffset,SEEK_SET);


                // Allocating memory for section's flag
                u8 sectionFlags[16];

                for ( u32 i=0;i<numOfSections;i++){

                    if(fread(&elf64Shdr,1,sizeof(Elf64_Shdr),fp)!=sizeof(Elf64_Shdr))
                        debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
                    else{
                        printf("(%d)-------%s--------\n",i,shStrings + elf64Shdr.sh_name);
                        display("    Type:  ",DISPLAY_COLOR_ORANGE);  
                        printf("%s\n",get_elf_section_type(elf64Shdr.sh_type));

                        get_elf_section_flag(elf64Shdr.sh_flags,sectionFlags,16);
                        
                        display("    Flags:  ",DISPLAY_COLOR_ORANGE);
                        printf("%s\n",sectionFlags);
                        
                        display("    Address:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%016x\n",elf64Shdr.sh_addr);
                        
                        display("    Offset:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf64Shdr.sh_offset);

                        display("    Size:  ",DISPLAY_COLOR_ORANGE);
                        printf("    Size:  %d(B)\n",elf64Shdr.sh_size);
                        
                        display("    Align:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf64Shdr.sh_addralign);
                        
                        display("    Link:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf64Shdr.sh_link);
                        
                        display("    Info:  ",DISPLAY_COLOR_ORANGE);
                        printf("0x%08x\n",elf64Shdr.sh_info);
                        
                        display("    EntSize:  ",DISPLAY_COLOR_ORANGE);
                        printf("%d(B)\n",elf64Shdr.sh_entsize);

                    }
                }
                // Freeing the allocated memory for the section's names
                free(shStrings);
            }
	    }else
	        debug("Invalid ELF class, cannot parse sections%x\n",DEBUG_STATUS_ERROR);
	}
}


/* Parse an ELF section */
void parse_elf_section(FILE *fp, u32 sectionsOffset, u32 sectionIdx, u8 elfClass){

    //TODO section name

    // Allocating memory for section's flag
    u8 sectionFlags[16];

    if(elfClass==ELFCLASS32){

        // Seeking to the section metadata
        fseek(fp,sectionsOffset+sectionIdx*sizeof(Elf32_Shdr),SEEK_SET);

        Elf32_Shdr elf32Shdr;

        if(fread(&elf32Shdr,1,sizeof(Elf32_Shdr),fp)!=sizeof(Elf32_Shdr))
            debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
        else{
            printf("-------%d--------\n",elf32Shdr.sh_name);
            printf("    Type:  %s\n",get_elf_section_type(elf32Shdr.sh_type));

            get_elf_section_flag(elf32Shdr.sh_flags,sectionFlags,16);
            printf("    Flags:  %s\n",sectionFlags);
            printf("    Address:  0x%016x\n",elf32Shdr.sh_addr);
            printf("    Offset:  0x%08x\n",elf32Shdr.sh_offset);
            printf("    Size:  %d(B)\n",elf32Shdr.sh_size);
            printf("    Align:  0x%08x\n",elf32Shdr.sh_addralign);
            printf("    Link:  0x%08x\n",elf32Shdr.sh_link);
            printf("    Info:  0x%08x\n",elf32Shdr.sh_info);
            printf("    EntSize: %d(B)\n",elf32Shdr.sh_entsize);
        }

    }else if(elfClass==ELFCLASS64){

        // Seeking to the section metadata
        fseek(fp,sectionsOffset+sectionIdx*sizeof(Elf64_Shdr),SEEK_SET);

        Elf64_Shdr elf64Shdr;

        if(fread(&elf64Shdr,1,sizeof(Elf64_Shdr),fp)!=sizeof(Elf64_Shdr))
            debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
        else{
            printf("-------%d--------\n",elf64Shdr.sh_name);
            printf("    Type:  %s\n",get_elf_section_type(elf64Shdr.sh_type));

            get_elf_section_flag(elf64Shdr.sh_flags,sectionFlags,16);
            printf("    Flags:  %s\n",sectionFlags);
            printf("    Address:  0x%016x\n",elf64Shdr.sh_addr);
            printf("    Offset:  0x%08x\n",elf64Shdr.sh_offset);
            printf("    Size:  %d(B)\n",elf64Shdr.sh_size);
            printf("    Align:  0x%08x\n",elf64Shdr.sh_addralign);
            printf("    Link:  0x%08x\n",elf64Shdr.sh_link);
            printf("    Info:  0x%08x\n",elf64Shdr.sh_info);
            printf("    EntSize: %d(B)\n",elf64Shdr.sh_entsize);
        }
    }else
        debug("Invalid ELF class, cannot parse sections%x\n",DEBUG_STATUS_ERROR);
}


/* Parse ELF segments */
void parse_elf_segments(FILE * fp ,u32 segmentOffset, u32 numOfSegments, u8 elfClass){


	if(!segmentOffset)
    	debug("No segments\n",DEBUG_STATUS_INF);
    else{

        if (elfClass == ELFCLASS32) {
            // Seeking to the segments table
            fseek(fp, segmentOffset, SEEK_SET);

            // Reading the segments
            Elf32_Phdr elf32Phdr;
            printf("%-10s%-10s%-15s%-15s%-15s%-25s%-10s%-10s\n", "Type", "Offset","VirAddr","PhyAddr","fSize","mSize","Flags","Align");

            // Buffers for segments flag
            u8 segmentFlag[10];

            for ( u32 i=0 ; i<numOfSegments;i++ ){
                fread(&elf32Phdr,1,sizeof(Elf32_Phdr),fp);
                get_elf_segment_flag(elf32Phdr.p_flags , segmentFlag , 10);
                printf("%-10s0x%-10x0x%-15x0x%-15x%-15d%-25d%-10s0x%-10x\n", get_elf_segment_type(elf32Phdr.p_type),elf32Phdr.p_offset,elf32Phdr.p_vaddr,elf32Phdr.p_paddr,elf32Phdr.p_filesz,elf32Phdr.p_memsz,segmentFlag,elf32Phdr.p_align);
            }
        }
        else if (elfClass == ELFCLASS64){

            // Seeking to the segments table
            fseek(fp, segmentOffset, SEEK_SET);

            // Reading the segments
            Elf64_Phdr elf64Phdr;
            printf("%-10s%-10s%-15s%-15s%-15s%-25s%-10s%-10s\n", "Type", "Offset","VirAddr","PhyAddr","fSize","mSize","Flags","Align");

            // Buffers for segment flag
            u8 segmentFlag[10];

            for ( u32 i=0 ; i<numOfSegments;i++ ){
                fread(&elf64Phdr,1,sizeof(Elf64_Phdr),fp);
                get_elf_segment_flag(elf64Phdr.p_flags , segmentFlag , 10);
                printf("%-10s0x%-10x0x%-15x0x%-15x%-15d%-25d%-10s0x%-10x\n", get_elf_segment_type(elf64Phdr.p_type),elf64Phdr.p_offset,elf64Phdr.p_vaddr,elf64Phdr.p_paddr,elf64Phdr.p_filesz,elf64Phdr.p_memsz,segmentFlag,elf64Phdr.p_align);
            }
        }
        else
            debug("Invalid ELF class\n",DEBUG_STATUS_ERROR);
    }
}


/* Parse ELF symbols */
void parse_elf_symbols(FILE * fp , u32 symbolTableOffset , u8 elfClass){


    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);

    if (elfClass == ELFCLASS32){

        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if section headers table exist
        if (! elf32Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            /*
            * Seeking to the start of the section names.
            */
            fseek(fp, elf32Ehdr.e_shoff + elf32Ehdr.e_shentsize * elf32Ehdr.e_shstrndx, SEEK_SET);


            // Reading the section header string table entry
            Elf32_Shdr elf32Shdr;
            fread(&elf32Shdr, 1, sizeof(Elf32_Shdr), fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 *shStrings = malloc(elf32Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else {

                // Seek to the section header strings by using the offset of the entry
                fseek(fp, elf32Shdr.sh_offset, SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings, 1, elf32Shdr.sh_size, fp);


                // Looking for sections that are type of symbol table

                // Seeking to the start of the sections table
                fseek(fp, elf32Ehdr.e_shoff, SEEK_SET);


                for (u32 i = 0; i < elf32Ehdr.e_shnum; i++) {

                    fread(&elf32Shdr, 1, sizeof(Elf32_Shdr), fp);

                    if (elf32Shdr.sh_type == SHT_SYMTAB) {

                        printf("\nSymbols of section '%s' are: \n",shStrings+elf32Shdr.sh_name);
                        printf("-------------------------------\n");


                        /* Names of symbols are in string table section */

                        // First reading strtab section
                        Elf32_Shdr strtabSecHeader;

                        // Seeking to strtab section entry, link member contains the
                        // index of strtab.
                        fseek(fp,elf32Ehdr.e_shoff + elf32Ehdr.e_shentsize*elf32Shdr.sh_link ,SEEK_SET);
                        fread(&strtabSecHeader,1,sizeof(Elf32_Shdr),fp);

                        // Reading symbols names into a buffer
                        u8 * symbolsNames = malloc(strtabSecHeader.sh_size);
                        fseek(fp,strtabSecHeader.sh_offset,SEEK_SET);
                        fread(symbolsNames,1,strtabSecHeader.sh_size,fp);


                        // Seeking to the symbol table of the found section
                        fseek(fp,elf32Shdr.sh_offset,SEEK_SET);

                        // Symbol entry
                        Elf32_Sym elf32Sym;
                        printf("%-10s%-10s%-15s%-15s%-25s%-10s\n", "Value", "Size","Type","Binding","Index","Name");

                        u8 symbolBinding[10];
                        u8 symbolType[10];
                        u8 symbolOther[10];

                        // Number of symbols is total size divided by entry size
                        for ( u32 i=0; i< elf32Shdr.sh_size / elf32Shdr.sh_entsize ;i++){

                            fread(&elf32Sym,1,sizeof(Elf32_Sym),fp);

                            // kelfv_resolve_symbol_type_binding(elf32Sym.st_info,symbolType,10,symbolBinding,10);
                            // kelfv_resolve_symbol_other(elf32Sym.st_other,symbolOther,10);


                            if ( elf32Sym.st_shndx == 0 )
                                printf("0x%-10x0x%-10x%-10s%-10s%-10s%-10s%-25s\n",elf32Sym.st_value,elf32Sym.st_size,symbolType,symbolBinding,"UNK",symbolOther,symbolsNames + elf32Sym.st_name);
                            else
                                printf("0x%-10x0x%-10x%-10s%-10s%-10d%-10s%-25s\n",elf32Sym.st_value,elf32Sym.st_size,symbolType,symbolBinding,elf32Sym.st_shndx,symbolOther,symbolsNames + elf32Sym.st_name);

                        }

                        // Freeing allocated memory
                        free(symbolsNames);
                    }
                }
            }
        }

    }

    else if (elfClass== ELFCLASS64){

        // Reading ELF header
        Elf64_Ehdr elf64Ehdr;
        fread(&elf64Ehdr,1,sizeof(Elf64_Ehdr),fp);

        // Check if section headers table exist
        if (! elf64Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            /*
            * Seeking to the start of the section names.
            */
            fseek(fp, elf64Ehdr.e_shoff + elf64Ehdr.e_shentsize * elf64Ehdr.e_shstrndx, SEEK_SET);


            // Reading the section header string table entry
            Elf64_Shdr elf64Shdr;
            fread(&elf64Shdr, 1, sizeof(elf64Shdr), fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 *shStrings = malloc(elf64Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else {

                // Seek to the section header strings by using the offset of the entry
                fseek(fp, elf64Shdr.sh_offset, SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings, 1, elf64Shdr.sh_size, fp);


                // Looking for sections that are type of symbol table

                // Seeking to the start of the sections table
                fseek(fp, elf64Ehdr.e_shoff, SEEK_SET);


                for (u32 i = 0; i < elf64Ehdr.e_shnum; i++) {

                    fread(&elf64Shdr, 1, sizeof(Elf64_Shdr), fp);

                    if (elf64Shdr.sh_type == SHT_SYMTAB) {
                        //TODO, index of symbols
                        printf("\nSymbols of section '%s' are: \n",shStrings+elf64Shdr.sh_name);
                        printf("-------------------------------\n");


                        /* Names of symbols are in string table section */

                        // First reading strtab section
                        Elf64_Shdr strtabSecHeader;

                        // Seeking to strtab section entry, link member contains the
                        // index of strtab.
                        fseek(fp,elf64Ehdr.e_shoff + elf64Ehdr.e_shentsize*elf64Shdr.sh_link ,SEEK_SET);
                        fread(&strtabSecHeader,1,sizeof(Elf64_Shdr),fp);

                        // Reading symbols names into a buffer
                        u8 * symbolsNames = malloc(strtabSecHeader.sh_size);
                        fseek(fp,strtabSecHeader.sh_offset,SEEK_SET);
                        fread(symbolsNames,1,strtabSecHeader.sh_size,fp);


                        // Seeking to the symbol table of the found section
                        fseek(fp,elf64Shdr.sh_offset,SEEK_SET);

                        // Symbol entry
                        Elf64_Sym elf64Sym;
                        printf("%-10s%-10s%-15s%-15s%-25s%-10s%-15s\n", "Value", "Size","Type","Binding","Index","Visibility","Name");

                        u8 symbolBinding[10];
                        u8 symbolType[10];
                        u8 symbolOther[10];

                        // Number of symbols is total size divided by entry size
                        for ( u32 i=0; i< elf64Shdr.sh_size / elf64Shdr.sh_entsize ;i++){

                            fread(&elf64Sym,1,sizeof(Elf64_Sym),fp);

                            // kelfv_resolve_symbol_type_binding(elf64Sym.st_info,symbolType,10,symbolBinding,10);
                            // kelfv_resolve_symbol_other(elf64Sym.st_other,symbolOther,10);

                            if ( elf64Sym.st_shndx == 0 )
                                printf("0x%-10x0x%-10x%-10s%-10s%-10s%-10s%-25s\n",elf64Sym.st_value,elf64Sym.st_size,symbolType,symbolBinding,"UNK",symbolOther,symbolsNames + elf64Sym.st_name);
                            else
                                printf("0x%-10x0x%-10x%-10s%-10s%-10d%-10s%-25s\n",elf64Sym.st_value,elf64Sym.st_size,symbolType,symbolBinding,elf64Sym.st_shndx,symbolOther,symbolsNames + elf64Sym.st_name);

                        }

                        // Freeing allocated memory
                        free(symbolsNames);
                    }
                }
            }
        }
    }

    else
        printf("[ERR] Invalid ELF class 0x%x\n",elfClass);
}


/* Extract entries of each relocation table */
static void extract_relocation_entries(FILE * fp , u8 elfClass ,u64 relocationEntriesOffset, u64 sectionSize , u8 relocationType ){

    // Saving the current offset of the file pointer
    u64 currOff = ftell(fp);

    // Number of relocation entries
    u64 numEntries;

    u8 relocationTypeStr[20];

    // Seeking to the given offset
    fseek(fp,relocationEntriesOffset,SEEK_SET);

    if (relocationType == SHT_REL ){

        printf("Relocations of type 'REL': \n");

        printf("%-10s%-20s%-10s%-10s\n", "Offset", "Info","Type","SecIdx");

        if ( elfClass == ELFCLASS32){

            Elf32_Rel elf32Rel;
            numEntries = sectionSize / sizeof(Elf32_Rel);

            for( u32 i=0 ;i < numEntries; i++){
                fread(&elf32Rel , 1 , sizeof(Elf32_Rel) , fp);

                // kelfv_resolve_relocation_type(ELF32_R_TYPE(elf32Rel.r_info),relocationTypeStr,20);

                printf("0x%-10x0x%-10x%-20s%-10d\n", elf32Rel.r_offset, elf32Rel.r_info,relocationTypeStr,ELF32_R_SYM(elf32Rel.r_info));
            }
        }
        else if ( elfClass == ELFCLASS64){

            Elf64_Rel elf64Rel;
            numEntries = sectionSize / sizeof(Elf64_Rel);

            for( u32 i=0 ;i < numEntries; i++){
                fread(&elf64Rel , 1 , sizeof(Elf64_Rel) , fp);

                // kelfv_resolve_relocation_type(ELF64_R_TYPE(elf64Rel.r_info),relocationTypeStr,20);

                printf("0x%-10x0x%-10x%-20s%-10d\n", elf64Rel.r_offset, elf64Rel.r_info,relocationTypeStr,ELF64_R_SYM(elf64Rel.r_info));


            }
        }
    }
    else if (relocationType == SHT_RELA ){

        printf("Relocations of type 'RELA': \n");

        printf("%-10s%-20s%-10s%-10s\n", "Offset", "Info","Type","SecIdx");

        if ( elfClass == ELFCLASS32){

            Elf32_Rela elf32Rela;
            numEntries = sectionSize / sizeof(Elf32_Rela);


            for( u32 i=0 ;i < numEntries; i++){
                fread(&elf32Rela , 1 , sizeof(Elf32_Rel) , fp);

                // kelfv_resolve_relocation_type(ELF32_R_TYPE(elf32Rela.r_info),relocationTypeStr,20);

                printf("0x%-10x0x%-10x%-20s%-10d\n", elf32Rela.r_offset, elf32Rela.r_info,relocationTypeStr,ELF32_R_SYM(elf32Rela.r_info));

            }
        }
        else if ( elfClass == ELFCLASS64){

            Elf64_Rela elf64Rela;
            numEntries = sectionSize / sizeof(Elf64_Rela);

            for( u32 i=0 ;i < numEntries; i++){
                fread(&elf64Rela , 1 , sizeof(Elf64_Rela) , fp);

                // kelfv_resolve_relocation_type(ELF64_R_TYPE(elf64Rela.r_info),relocationTypeStr,20);

                printf("0x%-10x0x%-10x%-20s%-10d\n", elf64Rela.r_offset, elf64Rela.r_info,relocationTypeStr,ELF64_R_SYM(elf64Rela.r_info));
            }
        }

    }

    // Recovering back the offset
    fseek(fp,currOff,SEEK_SET);


}

/* Parse ELF relocations */
void parse_elf_relocs(FILE * fp, u8 elfClass){

    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);

    if (elfClass == ELFCLASS32) {

        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if section headers table exist
        if (! elf32Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            // Seeking to the start of the sections' table
            fseek(fp,elf32Ehdr.e_shoff,SEEK_SET);


            // Looping through the sections and find those sections that are REL or RELA
            Elf32_Shdr elf32Shdr;


            for ( u32 i=0; i< elf32Ehdr.e_shnum ; i++){
                fread(&elf32Shdr,1,sizeof(Elf32_Shdr),fp);

                if (elf32Shdr.sh_type==SHT_REL || elf32Shdr.sh_type==SHT_RELA)
                    extract_relocation_entries(fp,ELFCLASS32,elf32Shdr.sh_offset, elf32Shdr.sh_size ,elf32Shdr.sh_type);

            }

        }

    } else  if (elfClass == ELFCLASS64) {

        // Reading ELF header
        Elf64_Ehdr elf64Ehdr;
        fread(&elf64Ehdr,1,sizeof(Elf64_Ehdr),fp);

        // Check if section headers table exist
        if (! elf64Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            // Seeking to the start of the sections' table
            fseek(fp,elf64Ehdr.e_shoff,SEEK_SET);

            // Looping through the sections and find those sections that are REL or RELA
            Elf64_Shdr elf64Shdr;

            for ( u32 i=0; i< elf64Ehdr.e_shnum ; i++){
                fread(&elf64Shdr,1,sizeof(Elf64_Shdr),fp);

                if (elf64Shdr.sh_type==SHT_REL || elf64Shdr.sh_type==SHT_RELA)
                    extract_relocation_entries(fp,ELFCLASS64,elf64Shdr.sh_offset, elf64Shdr.sh_size ,elf64Shdr.sh_type);
            }
        }

    } else
        printf("[ERR] Invalid ELF class 0x%x\n",elfClass);

}


/* This function simply dumps the given number of raw bytes */
void pe_parse_raw_bytes(FILE *fp, u32 rawBytesOffset, u32 nofRawBytes){

    fseek(fp,rawBytesOffset,SEEK_SET);

    // Allocate buffer for reading the raw bytes
    u8 * rawBytesBuff = malloc(nofRawBytes);


    if(!rawBytesBuff){
        debug("Cannot dump raw bytes (MemoryAllocError!)\n",DEBUG_STATUS_ERROR);
    }else{

        if(fread(rawBytesBuff , 1, nofRawBytes ,fp) != nofRawBytes ){
            debug("Cannot read raw bytes from the file\n",DEBUG_STATUS_ERROR);
        }else{
            printf("\t\t    -------\t\t\t\t\t\t    -------\n");
            printf("\t\t    |Bytes|\t\t\t\t\t\t    |ASCII|\n");
            printf("\t\t    -------\t\t\t\t\t\t    -------\n");


            // TODO bug of ASCII print if bytes are less than 16
            for(u32 i=0;i<nofRawBytes;i++){
                if(i%16==0)
                    printf("%08x: ",rawBytesOffset);        
                printf("%02x ",rawBytesBuff[i]);
                
                if((i+1)%16==0){
                    printf("\t");
                    for(u32 j=-15;i+j<=i;j++){
                        // Print only printable characters
                        if(rawBytesBuff[i+j]>=32 && rawBytesBuff[i+j]<=126)
                            printf("%c ",rawBytesBuff[i+j]);
                    }
                    printf("\n");
                    rawBytesOffset+=16;
                }
            }
            if(nofRawBytes<16){
                printf("\t\t\t\t\t\t\t");
                for(u32 i=0;i<nofRawBytes;i++){
                    // Print only printable characters
                    if(rawBytesBuff[i]>=32 && rawBytesBuff[i]<=126)
                        printf("%c ",rawBytesBuff[i]);
                    
                }
                printf("\n");
            }
            printf("\n");
        }
        free(rawBytesBuff);
    }
}






