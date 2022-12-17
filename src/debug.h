#ifndef DEBUG_H
#define DEBUG_H


/* Different status levels for debugging */
#define DEBUG_STATUS_INF 1		/* Informative messaging */
#define DEBUG_STATUS_ERROR 2	/* Error messaging */
#define DEBUG_STATUS_WARNING 3	/* Warning messaging */


/* Different display colors */ 
#define DISPLAY_COLOR_RED 0
#define DISPLAY_COLOR_GREEN_YELLOW 1
#define DISPLAY_COLOR_ORANGE 2
#define DISPLAY_COLOR_BLUE 3
#define DISPLAY_COLOR_PURPLE 4
#define DISPLAY_COLOR_CYAN 5
#define DISPLAY_COLOR_WHITE 6
#define DISPLAY_COLOR_BLACK 7




/* Perform debugging costomized based on the given status */
void debug(u8 * mess, u8 status);

/* Display a message with a given color */
void display(u8 *mess,u8 color);




#endif

