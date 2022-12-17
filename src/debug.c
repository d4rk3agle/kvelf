#include <stdio.h>
#include "./types.h"
#include "./debug.h"



/* Perform debugging costomized based on the given status */
void debug(u8 * mess, u8 status){
	if(status==DEBUG_STATUS_INF)
		printf("[0;35m[Info][0m %s",mess);
	else if (status == DEBUG_STATUS_ERROR)
		printf("[0;31m[Error][0m %s",mess);
	else if (status == DEBUG_STATUS_WARNING)
		printf("[0;33m[WARN][0m %s",mess);
}


/* Display a message with a given color */
void display(u8 *mess,u8 color){
	if(color==DISPLAY_COLOR_RED)
		printf("[0;31m%s[0m",mess);
	else if(color==DISPLAY_COLOR_GREEN_YELLOW)
		printf("[0;32m%s[0m",mess);
	else if(color==DISPLAY_COLOR_ORANGE)
		printf("[0;33m%s[0m",mess);
	else if(color==DISPLAY_COLOR_BLUE)
		printf("[0;34m%s[0m",mess);
	else if(color==DISPLAY_COLOR_PURPLE)
		printf("[0;35m%s[0m",mess);
	else if(color==DISPLAY_COLOR_CYAN)
		printf("[0;36m%s[0m",mess);
	else if(color==DISPLAY_COLOR_WHITE)
		printf("[0;37m%s[0m",mess);
	else if(color==DISPLAY_COLOR_BLACK)
		printf("[0;38m%s[0m",mess);
}

