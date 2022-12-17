#ifndef CLI_H
#define CLI_H

#include <regex.h>
#include "./types.h"



#define KVELF_INPUT_CMD_MAX_LENGTH 70


#define KVELF_CMD_REGEX_FILE_IDX 0
#define KVELF_CMD_REGEX_HEADER_IDX 1
#define KVELF_CMD_REGEX_SECTIONS_IDX 2
#define KVELF_CMD_REGEX_SYMBOLS_IDX 3
#define KVELF_CMD_REGEX_DYNAMIC_SYMBOLS_IDX 4
#define KVELF_CMD_REGEX_SEGMENTS_IDX 5
#define KVELF_CMD_REGEX_RELOCS_IDX 6
#define KVELF_CMD_REGEX_EXIT_IDX 7
#define KVELF_CMD_REGEX_ABST_IDX 8
#define KVELF_CMD_REGEX_VISUALIZE_IDX 9
#define KVELF_CMD_REGEX_LIST_SECTIONS_IDX 10
#define KVELF_CMD_REGEX_LIST_SEGMENTS_IDX 11
#define KVELF_CMD_REGEX_LIST_SYMBOLS_IDX 12
#define KVELF_CMD_REGEX_LIST_RELOCS_IDX 13
#define KVELF_CMD_REGEX_SEEK_IDX 14
#define KVELF_CMD_REGEX_PARSE_RAW_BYTES_IDX 15
#define KVELF_CMD_REGEX_PARSE_IDX 16
#define KVELF_CMD_REGEX_PARSE_AT_IDX 17
#define KVELF_CMD_REGEX_HELP_IDX 18


/* Compiling the regexes of the command line's commands */
regex_t * kvelf_compile_commandline(void);



/* This function splits the given string to tokens and returns the desired token
specified by the index */
u8 * get_word_in_string_by_idx(u8 * givenString,s32 idx);



/* Printing the help for the CLI commands */
void print_cli_help(void);


#endif

