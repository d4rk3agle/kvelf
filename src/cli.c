#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "./cli.h"
#include "./debug.h"



#define KVELF_CMD_COUNT 15

#define KVELF_CMD_REGEX_FILE_IDX 0
#define KVELF_CMD_REGEX_FILE_CMD "\\s*file\\s*[a-zA-Z_]\\s*"

#define KVELF_CMD_REGEX_HEADER_IDX 1
#define KVELF_CMD_REGEX_HEADER_CMD "\\s*header\\|h\\s*"

#define KVELF_CMD_REGEX_SECTIONS_IDX 2
#define KVELF_CMD_REGEX_SECTIONS_CMD "\\s*sections\\s*"

#define KVELF_CMD_REGEX_SYMBOLS_IDX 3
#define KVELF_CMD_REGEX_SYMBOLS_CMD "\\s*symbols\\s*"

#define KVELF_CMD_REGEX_DYNAMIC_SYMBOLS_IDX 4
#define KVELF_CMD_REGEX_DYNAMIC_SYMBOLS_CMD "\\s*dynsymbols\\s*"

#define KVELF_CMD_REGEX_SEGMENTS_IDX 5
#define KVELF_CMD_REGEX_SEGMENTS_CMD "\\s*segments\\s*"

#define KVELF_CMD_REGEX_RELOCS_IDX 6
#define KVELF_CMD_REGEX_RELOCS_CMD "\\s*relocs\\s*"

#define KVELF_CMD_REGEX_EXIT_IDX 7
#define KVELF_CMD_REGEX_EXIT_CMD "\\s*exit\\|quit\\|q\\s*"


#define KVELF_CMD_REGEX_ABST_IDX 8
#define KVELF_CMD_REGEX_ABST_CMD "\\s*abst\\s*"



#define KVELF_CMD_REGEX_VISUALIZE_IDX 9
#define KVELF_CMD_REGEX_VISUALIZE_CMD "\\s*visualize\\|V\\s*"


#define KVELF_CMD_REGEX_LIST_SECTIONS_IDX 10
#define KVELF_CMD_REGEX_LIST_SECTIONS_CMD "\\s*ls\\s*"


#define KVELF_CMD_REGEX_LIST_SEGMENTS_IDX 11
#define KVELF_CMD_REGEX_LIST_SEGMENTS_CMD "\\s*lsg\\s*"


#define KVELF_CMD_REGEX_LIST_SYMBOLS_IDX 12
#define KVELF_CMD_REGEX_LIST_SYMBOLS_CMD "\\s*lsym\\s*"

#define KVELF_CMD_REGEX_LIST_RELOCS_IDX 13
#define KVELF_CMD_REGEX_LIST_RELOCS_CMD "\\s*lr\\s*"

#define KVELF_CMD_REGEX_SEEK_IDX 14
#define KVELF_CMD_REGEX_SEEK_CMD "\\s*\\(seek\\|s\\)\\s*[0-9][0-9]*\\s*"


#define KVELF_CMD_REGEX_PARSE_RAW_BYTES_IDX 15
#define KVELF_CMD_REGEX_PARSE_RAW_BYTES_CMD "\\s*rb\\s*[0-9][0-9]*\\s*"

#define KVELF_CMD_REGEX_PARSE_IDX 16
#define KVELF_CMD_REGEX_PARSE_CMD "\\s*parse\\|p\\s*"

#define KVELF_CMD_REGEX_PARSE_AT_IDX 17
#define KVELF_CMD_REGEX_PARSE_AT_CMD "\\s*parse\\|p\\s*[0-9][0-9]*\\s*"

#define KVELF_CMD_REGEX_HELP_IDX 18
#define KVELF_CMD_REGEX_HELP_CMD "\\s*help\\|\\?\\s*"


// #define KVELF_CMD_REGEX_HELP_CMD "\\s*?\\s*"


regex_t kvelfCommandsRegexes[KVELF_CMD_COUNT];



/* Compiling the regexes of the command line's commands */
regex_t * kvelf_compile_commandline(void){

    

    if ( kvelfCommandsRegexes && !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_FILE_IDX],KVELF_CMD_REGEX_FILE_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_HEADER_IDX],KVELF_CMD_REGEX_HEADER_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_EXIT_IDX],KVELF_CMD_REGEX_EXIT_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_SECTIONS_IDX],KVELF_CMD_REGEX_SECTIONS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_SYMBOLS_IDX],KVELF_CMD_REGEX_SYMBOLS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_SEGMENTS_IDX],KVELF_CMD_REGEX_SEGMENTS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_DYNAMIC_SYMBOLS_IDX],KVELF_CMD_REGEX_DYNAMIC_SYMBOLS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_RELOCS_IDX],KVELF_CMD_REGEX_RELOCS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_ABST_IDX],KVELF_CMD_REGEX_ABST_CMD,0) && 
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_VISUALIZE_IDX],KVELF_CMD_REGEX_VISUALIZE_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_LIST_SECTIONS_IDX],KVELF_CMD_REGEX_LIST_SECTIONS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_LIST_SEGMENTS_IDX],KVELF_CMD_REGEX_LIST_SEGMENTS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_LIST_SYMBOLS_IDX],KVELF_CMD_REGEX_LIST_SYMBOLS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_LIST_RELOCS_IDX],KVELF_CMD_REGEX_LIST_RELOCS_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_SEEK_IDX],KVELF_CMD_REGEX_SEEK_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_PARSE_RAW_BYTES_IDX],KVELF_CMD_REGEX_PARSE_RAW_BYTES_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_PARSE_IDX],KVELF_CMD_REGEX_PARSE_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_PARSE_AT_IDX],KVELF_CMD_REGEX_PARSE_AT_CMD,0) &&
             !regcomp(&kvelfCommandsRegexes[KVELF_CMD_REGEX_HELP_IDX],KVELF_CMD_REGEX_HELP_CMD,0)

             ){

        return kvelfCommandsRegexes;
    }

    return NULL;
}


/* This function splits the given string to tokens and returns the desired token
specified by the index */
u8 * get_word_in_string_by_idx(u8 * givenString, s32 idx){

    u8 * token = strtok(givenString," \t\n");
    idx--;

    while(idx>=0){
        token=strtok(NULL," \t\n");
        if(!token)
            return NULL;
        idx--;
    }
    return token;
}


/* Printing the help for the CLI commands */
void print_cli_help(void){

    display("visualize/V     Visualizing the file's content\n",DISPLAY_COLOR_CYAN);
    display("abst            Display file's abstract\n",DISPLAY_COLOR_CYAN);
    display("seek/s ADDR     Seeking to a new address\n",DISPLAY_COLOR_CYAN);
    display("parse/p         Parse data structure at the current addres(if any)\n",DISPLAY_COLOR_CYAN);
    display("parse/p ADDR    Parse data structure at the given addres(if any)\n",DISPLAY_COLOR_CYAN);
    display("rb COUNT        Display raw COUNT bytes from the current address\n",DISPLAY_COLOR_CYAN);
    display("ls              List sections\n",DISPLAY_COLOR_CYAN);
    display("lsg             List segments\n",DISPLAY_COLOR_CYAN);
    display("lr              List relocations\n",DISPLAY_COLOR_CYAN);
    display("help/?          Display help\n",DISPLAY_COLOR_CYAN);


}

