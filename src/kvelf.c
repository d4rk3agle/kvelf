#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./types.h"
#include "./debug.h"
#include "./cli.h"
#include "./elf.h"
#include "./parse.h"
#include "./error.h"

typedef struct elf_offsets{
	u32 elfHeaderOffset;	/* Offset of the ELF header */
	u32 elfSectionHeaderOffset;	/* Offset of the ELF section headers */
	u32 elfSegmentHeaderOffset;	/* Offset of the ELF segment headers */

}elf_offsets_t;


typedef struct section_metadata{
	u32 sName;	/* Name of the section */
	u64 sVAddr;	/* Section virtual address */
	u64	sOffset;	/* Offset of the section */
	u64 sSize;		/* Size of the section */
}section_metadata_t;


typedef struct kvelf_basic_params{
	u8 * filePath;	/* File's path */
	FILE * fp;		/* FILE hander */
	
	elf_offsets_t elfOffsets; /* Offsets of the ELF file */

	u8 elfHeaderSize;	/* Size of the ELF header */
	u8 elfClass; 	/* Class of the ELF (32/64 bits) */
	u8 elfEncoding;	/* Data encoding of the ELF */
	u16 elfFiletype;	/* Type of the ELF file */
	u16 elfMachine;		/* Machine of the ELF file */
	u32 elfFileVersion;	/* Version of the ELF file */
	u64	elfEntrypoint;	/* Entry point of the ELF file */
	u32 elfNumOfSections;	/* Number of sections */
	u32 elfNumOfSegments;	/* Number of segments */
	u32 elfSectionsNameIdx;	/* Section number of the section containing the section's names */
	u32 sectionsNameOffset;	/* Starting address of the sections' names table */
	section_metadata_t * elfSectionsMetadata;	/* Metadata sections */

}kvelf_basic_params_t;



/* This function perfroms the basic analysis of the ELF file */
void basic_analysis(kvelf_basic_params_t * kvelfp){

	if(!(kvelfp->fp = fopen(kvelfp->filePath,"rb"))){
		// TODO
		printf("[0;31m[Error][0m Cannot open the file \"%s\" (Busy/Permissions/Does not exist...)\n",kvelfp->filePath);
		exit(ERROR_CANNOT_OPEN_FILE);
	}

	debug("Analyzing file's ELF header...\n",DEBUG_STATUS_INF);

	// Setting its offsets
	kvelfp->elfOffsets.elfHeaderOffset = 0; 

	// Reading ELF header's 16 byte metadata
	u8 elfHeader16bytes[16];
	if(fread(elfHeader16bytes,1,16,kvelfp->fp)!=16){
		debug("Cannot read ELF header 16 byte metadata\n",DEBUG_STATUS_ERROR);
		exit(ERROR_CANNOT_READ_FILE);
	}

	// Check if the ELF file is valid
	if(!(elfHeader16bytes[0]==0x7f && elfHeader16bytes[1]=='E' && elfHeader16bytes[2]=='L' && elfHeader16bytes[3]=='F')){
		debug("Specified file is not an ELF file\n",DEBUG_STATUS_ERROR);
		exit(ERROR_NOT_VALID_FILE);
	}

	// Setting ELF class
	kvelfp->elfClass=elfHeader16bytes[EI_CLASS];

	// Setting ELF data enconding
	kvelfp->elfEncoding=elfHeader16bytes[EI_DATA];

	/* Reading the ELF header */
	
	// Seeking to the first
	fseek(kvelfp->fp,0,SEEK_SET);

	if(kvelfp->elfClass==ELFCLASS32){
		
		Elf32_Ehdr elf32Header;
		if(fread(&elf32Header,1,sizeof(Elf32_Ehdr),kvelfp->fp)!=sizeof(Elf32_Ehdr)){
			debug("Cannot read ELF header",DEBUG_STATUS_ERROR);
			exit(ERROR_CANNOT_READ_FILE);
		}

		// Setting ELF data enconding
		kvelfp->elfFiletype=elf32Header.e_type;

		// Setting ELF machine 
		kvelfp->elfMachine=elf32Header.e_machine;

		// Setting ELF version 
		kvelfp->elfFileVersion=elf32Header.e_version;

		// Setting ELF entrypoint 
		kvelfp->elfEntrypoint=elf32Header.e_entry;

		// Setting ELF file header size
		kvelfp->elfHeaderSize=sizeof(Elf32_Ehdr);

		// Secting ELF section header offset
		kvelfp->elfOffsets.elfSectionHeaderOffset=elf32Header.e_shoff;

		// Setting ELF segment header offset
		kvelfp->elfOffsets.elfSegmentHeaderOffset=elf32Header.e_phoff;


		// Setting ELF number of sections
		kvelfp->elfNumOfSections=elf32Header.e_shnum;
		
		// Setting ELF number of segments 
		kvelfp->elfNumOfSegments=elf32Header.e_phnum;

		// Setting ELF section index of the section containing sections' names
		kvelfp->elfSectionsNameIdx=elf32Header.e_shstrndx;

	}else if(kvelfp->elfClass==ELFCLASS64){
		
		Elf64_Ehdr elf64Header;
		if(fread(&elf64Header,1,sizeof(Elf64_Ehdr),kvelfp->fp)!=sizeof(Elf64_Ehdr)){
			debug("Cannot read ELF header",DEBUG_STATUS_ERROR);
			exit(ERROR_CANNOT_READ_FILE);
		}

		// Setting ELF data enconding
		kvelfp->elfFiletype=elf64Header.e_type;

		// Setting ELF machine 
		kvelfp->elfMachine=elf64Header.e_machine;

		// Setting ELF version 
		kvelfp->elfFileVersion=elf64Header.e_version;

		// Setting ELF entrypoint 
		kvelfp->elfEntrypoint=elf64Header.e_entry;

		// Setting ELF file header size
		kvelfp->elfHeaderSize=sizeof(Elf64_Ehdr);

		// Sectting ELF section header offset
		kvelfp->elfOffsets.elfSectionHeaderOffset=elf64Header.e_shoff;

		// Sectting ELF segment header offset
		kvelfp->elfOffsets.elfSegmentHeaderOffset=elf64Header.e_phoff;

		// Setting ELF number of sections
		kvelfp->elfNumOfSections=elf64Header.e_shnum;
		
		// Setting ELF number of segments 
		kvelfp->elfNumOfSegments=elf64Header.e_phnum;

		// Setting ELF section index of the section containing sections' names
		kvelfp->elfSectionsNameIdx=elf64Header.e_shstrndx;
	}

	debug("Analyzing file's ELF sections\n",DEBUG_STATUS_INF);

	// Seeking to the start of the section header table for analyzing all the sections
    fseek(kvelfp->fp,kvelfp->elfOffsets.elfSectionHeaderOffset,SEEK_SET);

    // Allocating the sections' metadata
    kvelfp->elfSectionsMetadata=malloc(kvelfp->elfNumOfSections * sizeof(section_metadata_t));


	if (kvelfp->elfClass == ELFCLASS32){

	    Elf32_Shdr elf32Shr;

	    for (u32 i=0;i<kvelfp->elfNumOfSections;i++){

	        if(fread(&elf32Shr,1,sizeof(Elf32_Shdr),kvelfp->fp)!=sizeof(Elf32_Shdr))
	            debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
	        else{
	        	// Reading the sections' name offset from the desired section entry
	        	if(i==kvelfp->elfSectionsNameIdx)
	        		kvelfp->sectionsNameOffset=elf32Shr.sh_offset;
	        	kvelfp->elfSectionsMetadata[i].sName=elf32Shr.sh_name;
	        	kvelfp->elfSectionsMetadata[i].sVAddr=elf32Shr.sh_addr;
	        	kvelfp->elfSectionsMetadata[i].sOffset=elf32Shr.sh_offset;
	        	kvelfp->elfSectionsMetadata[i].sSize=elf32Shr.sh_size;

	        }
	    }
	}else if (kvelfp->elfClass == ELFCLASS64){

	    Elf64_Shdr elf64Shr;

	    for (u32 i=0;i<kvelfp->elfNumOfSections;i++){

	        if(fread(&elf64Shr,1,sizeof(Elf64_Shdr),kvelfp->fp)!=sizeof(Elf64_Shdr))
	            debug("Cannot read section ---\n",DEBUG_STATUS_ERROR);
	        else{
	        	// Reading the sections' name offset from the desired section entry
	        	if(i==kvelfp->elfSectionsNameIdx)
	        		kvelfp->sectionsNameOffset=elf64Shr.sh_offset;
	        	kvelfp->elfSectionsMetadata[i].sName=elf64Shr.sh_name;
	        	kvelfp->elfSectionsMetadata[i].sVAddr=elf64Shr.sh_addr;
	        	kvelfp->elfSectionsMetadata[i].sOffset=elf64Shr.sh_offset;
	        	kvelfp->elfSectionsMetadata[i].sSize=elf64Shr.sh_size;

	        }
	    }
	}


}



/* Graphical representaion of the ELF file's various parts */
void visualize_elf_file(kvelf_basic_params_t * kvelfp){


	// Temporary buffer for concatinating multiple values
	u8 tempBuff[100];

	//TODO size relative algorithm



	//TODO size is in the header
	display("\t\t\t\t------------------------------------------\n",DISPLAY_COLOR_RED);
	display("\t\t\t\t|",DISPLAY_COLOR_RED);
	printf("0x%016x(%dB)",kvelfp->elfOffsets.elfHeaderOffset,kvelfp->elfHeaderSize);
	display("                 |\n",DISPLAY_COLOR_RED);
	display("\t\t\t\t|                ELF Header              |\n",DISPLAY_COLOR_RED);
	display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_RED);

	if(kvelfp->elfOffsets.elfSegmentHeaderOffset){
		display("\t\t\t\t------------------------------------------\n",DISPLAY_COLOR_ORANGE);
		display("\t\t\t\t|",DISPLAY_COLOR_ORANGE);
		printf("0x%016x",kvelfp->elfOffsets.elfSegmentHeaderOffset);
		display("                      |\n",DISPLAY_COLOR_ORANGE);
		display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_ORANGE);
		display("\t\t\t\t|            Segment Headers             |\n",DISPLAY_COLOR_ORANGE);
		display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_ORANGE);
	}

	if(kvelfp->elfOffsets.elfSectionHeaderOffset){

		display("\t\t\t\t------------------------------------------\n",DISPLAY_COLOR_CYAN);
		display("\t\t\t\t|",DISPLAY_COLOR_CYAN);
		printf("0x%016x",kvelfp->elfOffsets.elfSectionHeaderOffset);
		display("                      |\n",DISPLAY_COLOR_CYAN);
		display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_CYAN);
		display("\t\t\t\t|             Section Headers            |\n",DISPLAY_COLOR_CYAN);
		display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_CYAN);
		display("\t\t\t\t------------------------------------------\n",DISPLAY_COLOR_CYAN);		
	}
	

	printf("\n\n");
	
	if(kvelfp->elfOffsets.elfSectionHeaderOffset){

		// Seeking to the start of the sections' names
		fseek(kvelfp->fp,kvelfp->sectionsNameOffset,SEEK_SET);
		//TODO
		u8 sectionNameBuff[50];
		u32 idx=0;


		for(u32 i=0;i<kvelfp->elfNumOfSections;i++){

			// Zeroing out the buffer
			for(u32 i=0;i<50;i++)
				sectionNameBuff[i]=0;
			idx=0;

			// Seeking to the section's name offset
			fseek(kvelfp->fp,kvelfp->sectionsNameOffset + kvelfp->elfSectionsMetadata[i].sName,SEEK_SET);

			// Reading section's name
			//TODO
			while(fread(sectionNameBuff+idx,1,1,kvelfp->fp)==1){
				if(sectionNameBuff[idx]==0)
					break;
				idx++;
			}

			if(i==0){
				printf("    Sections ---->");
				display("\t\t------------------------------------------\n",DISPLAY_COLOR_GREEN_YELLOW);

			}else
				display("\t\t\t\t------------------------------------------\n",DISPLAY_COLOR_GREEN_YELLOW);
			
			sprintf(tempBuff,"\t\t\t\t|0x%016llx(%09lldB)          |\n",kvelfp->elfSectionsMetadata[i].sOffset,kvelfp->elfSectionsMetadata[i].sSize);
			display(tempBuff,DISPLAY_COLOR_WHITE);
			display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_WHITE);
			if(i==0){
        		sprintf(tempBuff,"\t\t\t\t|%*s%*s|\n",22,"NULL",18,"");
			}else
        		sprintf(tempBuff,"\t\t\t\t|%*s%*s|\n",20+strlen(sectionNameBuff)/2,sectionNameBuff,20-strlen(sectionNameBuff)/2,"");

			display(tempBuff,DISPLAY_COLOR_WHITE);
			display("\t\t\t\t|                                        |\n",DISPLAY_COLOR_WHITE);
		}

	}


}

/* Display the abstract of the ELF file */
void display_elf_abstract(kvelf_basic_params_t * kvelfp){

	printf("\n");

    display("Entry: ",DISPLAY_COLOR_ORANGE);
	printf("0x%016llx\n",kvelfp->elfEntrypoint);

	display("Class: ",DISPLAY_COLOR_ORANGE);
	printf("%s\n",get_elf_class_string(kvelfp->elfClass));
    
    display("Encoding: ",DISPLAY_COLOR_ORANGE);	
	printf("%s\n",get_elf_dataencoding_string(kvelfp->elfEncoding));
    
    display("Type: ",DISPLAY_COLOR_ORANGE);
	printf("%s\n",get_elf_object_file_type(kvelfp->elfFiletype));

    display("Machine: ",DISPLAY_COLOR_ORANGE);
	printf("%s\n",get_elf_machine(kvelfp->elfMachine));
	
    display("File Version: ",DISPLAY_COLOR_ORANGE);
	printf("%d\n",kvelfp->elfFileVersion);
	
	printf("\n");
}



static s32 offset_is_section_metadata(u32 elfSectionsMetadataOffset, u32 elfNumOfSections, u8 elfClass,u64 offset){

	if(elfClass==ELFCLASS32){
		if(!(offset>=elfSectionsMetadataOffset && offset<elfSectionsMetadataOffset+elfNumOfSections*sizeof(Elf32_Shdr)))
			return -1;
		return (offset-elfSectionsMetadataOffset)/sizeof(Elf32_Shdr);
	}else if(elfClass==ELFCLASS64){

		if(!(offset>=elfSectionsMetadataOffset && offset<elfSectionsMetadataOffset+elfNumOfSections*sizeof(Elf64_Shdr)))
			return -1;

		return (offset-elfSectionsMetadataOffset)/sizeof(Elf64_Shdr);
	}
}

/* A wrapper function for raw parsing at a special address */
void parse_at(kvelf_basic_params_t * kvelfp, u64 offset){

	s32 sectionIdx;

	if(offset==kvelfp->elfOffsets.elfHeaderOffset)
		parse_elf_header(kvelfp->fp,kvelfp->elfOffsets.elfHeaderOffset);
	else if(offset==kvelfp->elfOffsets.elfSectionHeaderOffset)
		parse_elf_sections(kvelfp->fp,kvelfp->elfOffsets.elfSectionHeaderOffset,kvelfp->elfNumOfSections,kvelfp->elfSectionsNameIdx,kvelfp->elfClass);
	else if(offset==kvelfp->elfOffsets.elfSegmentHeaderOffset)
		parse_elf_segments(kvelfp->fp,kvelfp->elfOffsets.elfSegmentHeaderOffset,kvelfp->elfNumOfSegments,kvelfp->elfClass);
	else if((sectionIdx=offset_is_section_metadata(kvelfp->elfOffsets.elfSectionHeaderOffset,kvelfp->elfNumOfSections,kvelfp->elfClass,offset))!=-1){
		parse_elf_section(kvelfp->fp,kvelfp->elfOffsets.elfSectionHeaderOffset,sectionIdx,kvelfp->elfClass);
	}else
		debug("Nothing to be parsed at this address\n",DEBUG_STATUS_INF);
	
	// .. relocs

}




/* Prompts the cmd line for the user */
void prompt(kvelf_basic_params_t * kvelfp){

	// Compiling the CLI regexes
	regex_t * cliRegex = kvelf_compile_commandline();
	
	if(!cliRegex){
		debug("Cannot compile CLI commands",DEBUG_STATUS_ERROR);
		exit(ERROR_CANNOT_SETUP_CMD);
	}

	//TODO security of reading
	u8 usercmd[KVELF_INPUT_CMD_MAX_LENGTH];

	//TODO not covering whole range
	u64 fileOffset=0;


	/* Matching priority is important since the match finding is the case not the whole !!*/

	while(1){
		printf("0x%016llx> ",fileOffset);
		fgets(usercmd, KVELF_INPUT_CMD_MAX_LENGTH, stdin);
	
		if(regexec(&cliRegex[KVELF_CMD_REGEX_EXIT_IDX], usercmd, 0, NULL, 0)==0){
			printf("Bye:)!\n");
			exit(0);
		}
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_ABST_IDX], usercmd, 0, NULL, 0)==0)
			display_elf_abstract(kvelfp);
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_VISUALIZE_IDX], usercmd, 0, NULL, 0)==0)
			visualize_elf_file(kvelfp);
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_LIST_SYMBOLS_IDX], usercmd, 0, NULL, 0)==0)
			parse_elf_symbols(kvelfp->fp,0,kvelfp->elfClass);
		
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_LIST_SEGMENTS_IDX], usercmd, 0, NULL, 0)==0)
			parse_elf_segments(kvelfp->fp,kvelfp->elfOffsets.elfSegmentHeaderOffset,kvelfp->elfNumOfSegments,kvelfp->elfClass);
		
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_LIST_SECTIONS_IDX], usercmd, 0, NULL, 0)==0)
			parse_elf_sections(kvelfp->fp,kvelfp->elfOffsets.elfSectionHeaderOffset,kvelfp->elfNumOfSections,kvelfp->elfSectionsNameIdx,kvelfp->elfClass);

		else if(regexec(&cliRegex[KVELF_CMD_REGEX_HEADER_IDX], usercmd, 0, NULL, 0)==0)
			parse_elf_header(kvelfp->fp,kvelfp->elfOffsets.elfHeaderOffset);
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_LIST_RELOCS_IDX], usercmd, 0, NULL, 0)==0)
			parse_elf_relocs(kvelfp->fp,kvelfp->elfClass);
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_SEEK_IDX], usercmd, 0, NULL, 0)==0){
			u8 * givenNumber =  get_word_in_string_by_idx(usercmd,1);
			fileOffset = strtoull(givenNumber, NULL, 0);		
		}
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_PARSE_RAW_BYTES_IDX], usercmd, 0, NULL, 0)==0){
			u8 * givenBytesCount =  get_word_in_string_by_idx(usercmd,1);
			u32 givenBytes = strtol(givenBytesCount, NULL, 0);
			pe_parse_raw_bytes(kvelfp->fp,fileOffset,givenBytes);
		}
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_PARSE_AT_IDX], usercmd, 0, NULL, 0)==0){
			u8 * givenOffsetStr =  get_word_in_string_by_idx(usercmd,1);
			u64 givenOffset =(unsigned long long) strtoll(givenOffsetStr, NULL, 0);
			parse_at(kvelfp,givenOffset);
		}
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_PARSE_IDX], usercmd, 0, NULL, 0)==0)
			parse_at(kvelfp,fileOffset);
		else if(regexec(&cliRegex[KVELF_CMD_REGEX_HELP_IDX], usercmd, 0, NULL, 0)==0)
			print_cli_help();
	}
}





u32 main(u32 argc , u8 ** argv){
	
	if(argc==1){
		
		debug("Provide the file's path as the ARGV[1]\n",DEBUG_STATUS_ERROR);
		exit(ERROR_NO_FILE_PROVIDED);
	}

	/* Holding global parameters of the program during analysis */
	kvelf_basic_params_t kvelfp;

	kvelfp.filePath = argv[1];

	// Performing basic analysis
	basic_analysis(&kvelfp);

	// Starting the prompt
	prompt(&kvelfp);
	

}

