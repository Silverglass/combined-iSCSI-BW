/***********************************************************************

  OCTEON TOOLKITS                                                         
  Copyright (c) 2007 Cavium Networks. All rights reserved.

  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
  contains proprietary and confidential information of Cavium Networks
  and in some cases its suppliers.

  Any licensed reproduction, distribution, modification, or other use of
  this file or confidential information embodied in this file is subject
  to your license agreement with Cavium Networks. The applicable license
  terms can be found by contacting Cavium Networks or the appropriate
  representative within your company.

  All other use and disclosure is prohibited.

  Contact Cavium Networks at info@caviumnetworks.com for more information.

 ************************************************************************/ 

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-pip.h"
#include "cvmx-ciu.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-gmx.h"
#include "cvmx-asx.h"
#include "cvmx-uart.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-atomic.h"
#include "cvmx-helper.h"
#include "cvmx-npi.h"

#include "lib_octeon_shared.h"
#include "octeon_mem_map.h"
#include "elf.h"

#define ELF_BASE_ADDR 0x70000000

/* Use our version of printf instead of the C libraries. We don't
    want the per core banners */
#define printf(format, ...) uart_printf(0, format, ##__VA_ARGS__)

unsigned int dump_elf_info(unsigned char st_type);

#define GOTO_TOP  "\033[1;1H"   /* ESC[1;1H begins output at the top of the terminal (line 1) */
#define GOTO_BOTTOM "\033[100;1H"   /* ESC[1;1H begins output at the bottom of the terminal (actually line 100) */
#define GOTO_BOL  "\033[100D"   /* Go to beginning of line */
#define ERASE_EOL "\033[0K"     /* Erase to end of line */
#define ERASE_EOS "\033[0J"     /* Erase to end screen */
#define ERASE_WIN "\033[2J"     /* Erase the window */
#define REVERSE   "\033[7m"     /* Reverse the display */
#define NORMAL    "\033[0m"     /* Normal display */
#define SCROLL_FULL "\033[1;r"  /* Normal full-screen scrolling for statistics region */
#define SET_SCROLL_REGION(row) printf("\033[%d;r",row)   /* for command region */
#define CURSOR_ON  "\033[?25h"  /* Turn on cursor */
#define CURSOR_OFF "\033[?25l"  /* Turn off cursor */
#define GOTO_BOTTOM_x "\033[100;%dH" /* go to the bottom of the screen and posion x (supply to printf) */

char *tx_packet_type_lut[] = {
    "UDP",
    "help",     /* best to keep this last */
    0
};

typedef enum {
    DATA_TYPE_ABC=0,
    DATA_TYPE_ZERO,
    DATA_TYPE_INC,
    DATA_TYPE_DEC,
    DATA_TYPE_RAND,
    DATA_TYPE_HELP      /* best to keep this last */
} payload_t;

char *tx_payload_lut[] = {
    "abc",
    "zero",
    "inc",
    "dec",
    "rand",
    "help",     /* best to keep this last */
    0
};

char *on_off_lut[] = {
    "on",
    "off",
    0
};

char **numeric = NULL;  /* for displaying numeric types in PRINTTRANS */

typedef struct {
    char *command;
    char **lut;
} secondary_lut_lut_t;

secondary_lut_lut_t secondary_lut_lut[] = {
    {"tx.type ", tx_packet_type_lut},
    {"tx.payload ", tx_payload_lut},
    {"row", on_off_lut},
    {"hli", on_off_lut},
    {"freeze", on_off_lut},
    {0,0}
};

/* NOTE:  This array is used for command completion!!! */
char *help_commands[] = {
    "mem.read <address> <64 bit loc. count>    Read 64 bit words from the memory\n"
    "mem.set <address> <64 bit value>          Write 64 bit word to the memory\n"
    "list.func                                 List all the functions that can be called from command line\n"
    "list.object                               List all the global variables that can be accessed from command line\n"
    "<object>                                  Displays the current value of the object\n",
    "<object> = <value>                        Sets the object variable to value\n",
    "grep.func                                 greps the provided string within function names\n"
    "grep.object                               greps the provided string within object names\n"
    "help                                      Show the available commands\n",
    0
};

int                          help_frozen = 0;   /* set to stop display updates */
int                          default_start_port = 0;
int                          default_stop_port = CVMX_PIP_NUM_INPUT_PORTS-1;
int                          max_displayed_row = 1;
CVMX_SHARED uint64_t         cpu_clock_hz;

uint64_t total_display_updates=0;

#define MAX_ROW 100

/**
 * Put a single byte to uart port.
 *
 * @param uart_index Uart to write to (0 or 1)
 * @param ch         Byte to write
 */
static inline void uart_write_byte(int uart_index, uint8_t ch)
{
    cvmx_uart_lsr_t lsrval;

    /* Spin until there is room */
    do
    {
        lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));
        if (lsrval.s.thre == 0)
            cvmx_wait(10000);   /* Just to reduce the load on the system */
    }
    while (lsrval.s.thre == 0);

    /* Write the byte */
    cvmx_write_csr(CVMX_MIO_UARTX_THR(uart_index), ch);
}

#if 0
/**
 * Wait for the TX buffer to be empty
 *
 * @param uart_index Uart to check
 */
static void uart_wait_idle(int uart_index)
{
    cvmx_uart_lsr_t lsrval;

    /* Spin until there is room */
    do
    {
        lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));
        if (lsrval.s.temt == 0)
            cvmx_wait(10000);   /* Just to reduce the load on the system */
    }
    while (lsrval.s.temt == 0);
}
#endif

/**
 * Version of printf for direct uart output. This bypasses the
 * normal per core banner processing.
 *
 * @param uart_index Uart to write to
 * @param format     printf format string
 * @return Number of characters written
 */
int uart_printf(int uart_index, const char *format, ...) __attribute__ ((format(printf, 2, 3)));
int uart_printf(int uart_index, const char *format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    int i = result;
    char *ptr = buffer;
    while (i > 0)
    {
        if (*ptr == '\n')
            uart_write_byte(uart_index, '\r');
        uart_write_byte(uart_index, *ptr);
        ptr++;
        i--;
    }
    return result;
}


/**
 * Get a single byte from serial port.
 *
 * @param uart_index Uart to read from (0 or 1)
 * @return The byte read
 */
inline uint8_t uart_read_byte(int uart_index)
{
    /* Read and return the data. Zero will be returned if there is
        no data */
    cvmx_uart_lsr_t lsrval;
    lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));
    if (lsrval.s.dr)
        return cvmx_read_csr(CVMX_MIO_UARTX_RBR(uart_index));
    else
        return 0;
}

#define MAX_COMMAND 256
#define MAX_ARGUMENTS 8

#define MAX_HISTORY_LOG2 (8)
#define MAX_HISTORY (1<<MAX_HISTORY_LOG2)
#define MAX_HISTORY_MASK (MAX_HISTORY-1)
#define DEBUG_ESCAPE 0

static char command_history[MAX_HISTORY][MAX_COMMAND] = {{0,},};
static int history_index = 0;
static int history_lookup_index = 0;
static unsigned int cmd_len = 0;
static unsigned int cmd_pos = 0;
static char *cmd;
static int escape_saw_char=0;
static int escape_mode = 0;
static int find_mode = 0;
static int find_orig_cmd_pos = 0;
static int search_mode = 0;
static int debug_value = 0;
#define BIT_POS_SHOW_LOOKUP 0
#define BIT_MASK_SHOW_LOOKUP (1<<BIT_POS_SHOW_LOOKUP)
static int insert_mode = 0;
static int delete_mode = 0;
static int overwrite_once = 0;
static char **saved_avail_p = NULL;
static int saved_suffix_size = 0;
static int tab_mode = 0;
static char pattern[MAX_COMMAND] = {0,};
static int pattern_dir_delta=-1;
static int pattern_dir_reverse=0;
typedef struct {
    char cmd[MAX_COMMAND];
    unsigned int cmd_len;
    unsigned int cmd_pos;
} undo_t;
static undo_t undo = {{0,},0,0};

typedef struct
{
    char        str[MAX_COMMAND];
    uint64_t    number;
} argument_info_t;

unsigned int exec_command(char *command, argument_info_t *args, int argc);
char* get_func_name(char* func_name, unsigned int func_addr);
void lookup_str(char *str, unsigned char st_type);


/**
 * Parse a command into a its arguments
 *
 * @param cmd    Command to parse
 * @param args   Output of the arguments
 * @return Number of arguments
 */
static int parse_command(const char *cmd, argument_info_t args[MAX_ARGUMENTS])
{
    int num_args = 0;
    int ret=0;

    args[num_args].str[0] = 0;
    args[num_args].number = 0;

    while (*cmd)
    {
        if (*cmd != ' ')
        {
            int len = strlen(args[num_args].str);
            args[num_args].str[len] = *cmd;
            args[num_args].str[len+1] = 0;
            cmd++;
        }

        if ((*cmd == ' ') || (*cmd == 0))
        {
            uint64_t number = 0;

            if ((args[num_args].str[0] == '0') && (args[num_args].str[1] == 'x'))
            {
                /* Starts with 0x, so assume argument is a hex number */
#ifdef CVMX_ABI_N32
                if (sscanf(args[num_args].str+2, "%llx", &number) != 1)
                    printf("Parse error on argument: %s\n", args[num_args].str);
#else
                if (sscanf(args[num_args].str+2, "%lx", &number) != 1)
                    printf("Parse error on argument: %s\n", args[num_args].str);
#endif
            }
            else if (strchr(args[num_args].str, '.'))
            {
                /* There are periods in it. Assume it is an IP address */
                unsigned int p1, p2, p3, p4;
                if (sscanf(args[num_args].str, "%u.%u.%u.%u", &p1, &p2, &p3, &p4) == 4)
                    number = (p1<<24) | (p2<<16) | (p3<<8) | p4;
            }
            else if (strchr(args[num_args].str, ':'))
            {
                /* Colons, assume it is hex bytes */
                unsigned int b;
                unsigned int count;
                const char *ptr = args[num_args].str;
                while (*ptr && sscanf(ptr, "%x%n", &b, &count))
                {
                    number = (number<<8) | b;
                    ptr += count;
                    if (*ptr == ':')
                        ptr++;
                }
            }
            else
            {
                /* Don't have any idea, so try the automatic conversion */
#ifdef CVMX_ABI_N32
                ret = sscanf(args[num_args].str, "%lli", &number);
#else
                ret = sscanf(args[num_args].str, "%li", &number);
#endif
            }

            if(ret != 0) {
               args[num_args].number = number;
            }
            else if ((args[num_args].str[0] == '0') && (args[num_args].str[1] == 'x')) {
               args[num_args].number = number;
            }
            else {
	        args[num_args].number = (uint64_t)CAST64(args[num_args].str);
            }

            args[num_args].number = number;
            num_args++;
            args[num_args].str[0] = 0;

            while (*cmd == ' ')
                cmd++;
        }
    }

    return num_args;
}


/**
 * Process a command from the user
 *
 * @param cmd    Command to process
 */
static void process_command(const char *cmd)
{
    argument_info_t args[MAX_ARGUMENTS];
    char *command;
    uint64_t value;
    uint64_t start_port;
    uint64_t stop_port;


    SET_SCROLL_REGION(max_displayed_row);
    printf(GOTO_BOTTOM);

    int argc = parse_command(cmd, args);
    command = args[0].str;

    switch (argc)
    {
        case 1:
            start_port = default_start_port;
            stop_port = default_stop_port;
            value = 0;
            break;
        case 2:
            start_port = default_start_port;
            stop_port = default_stop_port;
            value = args[1].number;
            break;
        case 3:
            start_port = args[1].number;
            stop_port = args[1].number;
            value = args[2].number;
            break;
        case 4:
            start_port = args[1].number;
            stop_port = args[2].number;
            value = args[3].number;
            break;
        default:
            return;
    }

    printf("\n");

    #define PORT_RANGE_COMMAND(NAME, FIELD, VALUE)                  \
        else if (strcasecmp(command, NAME) == 0)                    \
        {                                                           \
            if (argc == 2)                                          \
                stop_port = start_port = value;                     \
            if (argc >= 3)                                          \
                stop_port = value;                                  \
            for (port=start_port; port<=stop_port; port++)          \
                FIELD = VALUE;                                      \
        }
    #define PORT_VALUE_COMMAND(NAME, FIELD)                         \
        else if (strcasecmp(command, NAME) == 0)                    \
        {                                                           \
            for (port=start_port; port<=stop_port; port++)          \
                if (argc >= 2)                                      \
                {                                                   \
                    FIELD = value;                                  \
                    build_packet(port_transmitter[port].output_data,\
                        port_transmitter[port].output_packet_size,  \
                        port_transmitter[port].output_packet_type,  \
                        port_transmitter[port].output_packet_payload,\
                        port);                                      \
                }                                                   \
                else if (port_state[port].display)                  \
                    printf("Port %2llu %s: %22llu 0x%016llx\n",     \
                           (ULL)port, NAME, (ULL)FIELD, (ULL)FIELD);\
        }
    #define TX_TYPE_COMMAND(NAME, FIELD, LUT)                                  \
        else if (strcasecmp(command, NAME) == 0)                               \
        {                                                                      \
            int type=0;                                                        \
            char *p = strrchr(cmd,' ');                                        \
            if (p) {                                                           \
                p++;                                                           \
                                                                               \
                switch (argc)                                                  \
                {                                                              \
                    case 1:                                                    \
                        start_port = default_start_port;                       \
                        stop_port = default_stop_port;                         \
                        break;                                                 \
                    case 2:                                                    \
                        start_port = args[1].number;                           \
                        stop_port = args[1].number;                            \
                        break;                                                 \
                    case 3:                                                    \
                    default:                                                   \
                        start_port = args[1].number;                           \
                        stop_port = args[2].number;                            \
                        break;                                                 \
                }                                                              \
                while (LUT[type]) {                                            \
                    if (strcasecmp(p, LUT[type]) == 0) {                       \
                        if (strcasecmp(p,"help") == 0)                         \
                            while (LUT[type]) type++;                          \
                        break;                                                 \
                    }                                                          \
                    type++;                                                    \
                }                                                              \
                if (LUT[type]) {                                               \
                    for (port=start_port; port<=stop_port; port++)             \
                    {                                                          \
                        FIELD = type;                                          \
                        build_packet(port_transmitter[port].output_data,       \
                                port_transmitter[port].output_packet_size,     \
                                port_transmitter[port].output_packet_type,     \
                                port_transmitter[port].output_packet_payload,  \
                                port);                                         \
                    }                                                          \
                }                                                              \
                else {                                                         \
                    printf(NAME " types:");                                    \
                    for(type=0;  LUT[type]; type++) printf(" %s",LUT[type]);   \
                    printf("\n");                                              \
                }                                                              \
            }                                                                  \
            else {                                                             \
                printf("Missing space before " NAME " type.\n");               \
            }                                                                  \
        }

    #define ROW_RANGE_COMMAND(NAME, FIELD, INVERT)                             \
        else if (strcasecmp(command, NAME) == 0)                               \
        {                                                                      \
            unsigned int start_row=0, end_row=0, row, row_and=1, row_or=0;     \
            char *p = strrchr(cmd,' ');                                        \
            printf(GOTO_TOP ERASE_EOS);                                        \
            switch (argc) {                                                    \
                case 1:                                                        \
                    start_row = 1;                                             \
                    end_row = MAX_ROW;                                         \
                    break;                                                     \
                case 2:                                                        \
                    start_row = args[1].number;                                \
                    end_row = args[1].number+1;                                \
                    break;                                                     \
                case 3:                                                        \
                    start_row = args[1].number;                                \
                    end_row = args[2].number+1;                                \
                    break;                                                     \
                default:                                                       \
                    start_row = 0;                                             \
                    end_row = 0;                                               \
                    printf("Too many arguments");                              \
                    break;                                                     \
            }                                                                  \
            if (start_row > MAX_ROW) start_row = MAX_ROW;                      \
            if (end_row > MAX_ROW) end_row = MAX_ROW;                          \
            if (p && strcasecmp(p, " off") == 0) {                             \
               if (INVERT) row_or=1;                                           \
               else row_and=0;                                                 \
            }                                                                  \
            else if (p && strcasecmp(p, " on") == 0) {                         \
                if (INVERT) row_and=0;                                         \
                else row_or=1;                                                 \
            }                                                                  \
            for (row=start_row; row<end_row; row++) {                          \
                FIELD ^= 1;                                                    \
                FIELD &= row_and;                                              \
                FIELD |= row_or;                                               \
            }                                                                  \
        }
    if (strcasecmp(command, "mem.read") == 0) {
      {
        uint64_t i;
	uint64_t loc;

        if(argc < 3)
           loc = 1;
	else
           loc = args[2].number;

        for(i=0;i<loc;i++) {
	    printf("mem location 0x%llx = 0x%llx\n", CAST64( (args[1].number + (i * 8)) ), CAST64(*( CASTPTR(uint64_t, (args[1].number + (i * 8))))) );
	}
      }
    }
    else if (strcasecmp(command, "mem.set") == 0) {
      printf("mem location 0x%llx = 0x%llx\n", CAST64(args[1].number), CAST64(*( CASTPTR(uint64_t, args[1].number))) );
	*( CASTPTR(uint64_t, args[1].number) ) = args[2].number;
	printf("mem location 0x%llx = 0x%llx\n", CAST64(args[1].number), CAST64(*( CASTPTR(uint64_t, args[1].number))) );
    }
    else if (strcasecmp(command, "list.func") == 0) {
	dump_elf_info(STT_FUNC);
    }
    else if (strcasecmp(command, "list.object") == 0) {
	dump_elf_info(STT_OBJECT);
    }
    else if (strcasecmp(command, "grep.func") == 0) {
        lookup_str(args[1].str, STT_FUNC);
    }
    else if (strcasecmp(command, "grep.object") == 0) {
        lookup_str(args[1].str, STT_OBJECT);
    }
    else if (strcasecmp(command, "help") == 0) {
            char **help_string_p;
            //printf(SCROLL_FULL);
            //printf(GOTO_TOP ERASE_EOS);
            //printf("Available Commands: (case insensitive)  Note: [<port range>] means [<first port> [<last port>]]\n\n");
            for (help_string_p=help_commands; *help_string_p; help_string_p++) {
                printf("%s",*help_string_p);
            }
            printf("\nMany vi style modes are available for command and history navigation.\n");
            printf("Use ARROW KEYS, HOME, END or ESC-h,ESC-j,ESC-k,ESC-l,ESC-0,ESC-$,ESC-w,ESC-b, or ESC-fx for navigation.\n");
            printf("Use TAB for commmand completion, multiple to cycle, or CTRL-D for a list of possible commands.\n");
            printf("Use ESC-i,ESC-A,ESC-a,ESC-c for insert mode, ESC-R,ESC-r for overwrite mode (behavior like vi).\n");
            printf("Use INSERT to toggle insert/overwrite mode, DELETE to delete, F1 for help.\n");
            printf("Use !!, !<num> or !<string> to repeat previous commands in the history.\n");
            printf("Use ::, :<num> or :<string> to recall previous commands in the history to current.\n");
            printf("Use ?<string>, /<string>, ESC-?<string>,ESC-/<string>,ESC-n,ESC-N to also recall to current.\n");
            printf("Use CTRL-l erase the screen, ESC-D to clear the rest of the current line.\n");
            printf("Use ESC-d<movement> to delete, ESC-~ to change case, ESC-u to undo (one level).\n");
            printf("See the vi man page for more info on the operation of various commands.\n");
            printf("\nNote: This program works best with a very wide and tall terminal window.\n");
    }
    else {
        exec_command(command, args, argc);
    }
    CVMX_SYNCWS;
    if (strcasecmp(command, "help") == 0) {
        printf("\nType 'enter' or any command to continue.\n");
        help_frozen = 1;
    }

    printf(CURSOR_OFF SCROLL_FULL GOTO_BOTTOM CURSOR_ON);
}

void process_input_draw_current()
{
    command_history[history_index][cmd_len] = 0;
    if (debug_value & BIT_MASK_SHOW_LOOKUP) {
        printf(CURSOR_OFF GOTO_BOTTOM "Cmd%4d%4d(%s)> ", history_lookup_index, history_index,
                delete_mode ? "DEL" : find_mode ? "FND" : escape_mode ? "ESC" : insert_mode ? "INS":"OVR");
    }
    else {
        printf(CURSOR_OFF GOTO_BOTTOM "Command%4d(%s)> ", history_index,
                delete_mode ? "DEL" : find_mode ? "FND" : escape_mode ? "ESC" : insert_mode ? "INS":"OVR");
    }

    printf(command_history[history_index]);
    /* Erase to end of line, put cursor at correct pos */
    printf(ERASE_EOL GOTO_BOTTOM_x CURSOR_ON, (int)(cmd_pos + sizeof("Command1234(OVR)> ")));
    return;
}

char *find_token_end(char *token)
{
    char *b;
    char *p=strchr(token,' ');
    if ((b=strchr(token,'[')) && (b<p)) p=b;    /* for 'tx.data[' style case */
    if (p==NULL)
        return (token + strlen(token));
    return (p+1);
}

void process_input_commit_character(char ch) {
    if (insert_mode) {
        if (cmd_len < MAX_COMMAND-1) {
            if (cmd_len > cmd_pos) {
                memmove(&cmd[cmd_pos+1], &cmd[cmd_pos], cmd_len-cmd_pos+1);
            }
            cmd[cmd_pos++] = ch;
            cmd_len++;
            uart_write_byte(0, ch);
        }
    }
    else {      /* overwrite mode */
        if (cmd_pos < MAX_COMMAND-1) {
            cmd[cmd_pos++] = ch;
            if (cmd_pos > cmd_len) cmd_len = cmd_pos;
            uart_write_byte(0, ch);
        }
    }
}

char **next_avail_p(char **avail_p, char **lut)
{
    if (avail_p == NULL) return lut;
    if (*++avail_p == 0) return lut;
    return avail_p;
}

void tab_complete(char *token_start, char **lut)
{       /* find longest common suffix, of those with matching prefixes */
    char **avail_p;
    char *p;
    int suffix_size=-1;
    char *suffix = NULL;
    int offset = cmd_pos - (token_start - cmd);
    int delta_pos=0;
    int printed=0;

    if (tab_mode==1) {
        if (saved_avail_p == NULL) {
            for (saved_avail_p = lut; *saved_avail_p; saved_avail_p++);
            saved_avail_p--;    /* initialize to the one before the end */
        }
        for (avail_p = next_avail_p(saved_avail_p,lut); avail_p != saved_avail_p; avail_p = next_avail_p(avail_p,lut)) {
            if (strncasecmp(token_start, *avail_p, offset)==0) {        /* prefix matches */
                suffix = *avail_p+offset;
                p=find_token_end(suffix);
                suffix_size = p - suffix;
                saved_avail_p = avail_p;
                delta_pos = suffix_size;
                if ((cmd_pos + saved_suffix_size) > MAX_COMMAND-1) {
                    saved_suffix_size=0;        /* this should never happen, but just in case... */
                }
                if ((cmd_pos + saved_suffix_size) > cmd_len) {
                    cmd_len = (cmd_pos + saved_suffix_size);
                }
                if (insert_mode) {
                    memmove(&cmd[cmd_pos], &cmd[cmd_pos+saved_suffix_size], saved_suffix_size);
                    cmd_len -= saved_suffix_size;
                }
                else {  /* in overwrite mode, at least cover leftover junk that we created with spaces */
                    memset(&cmd[cmd_pos], ' ', saved_suffix_size);
                }
                cmd[cmd_len]=0;
                saved_suffix_size = suffix_size;
                break;
            }
        }
    }
    else {
        if (tab_mode==2) printf ("\n");
        for (avail_p = lut; *avail_p && suffix_size; avail_p++) {
            if (strncasecmp(token_start, *avail_p, offset)==0) {        /* prefix matches */
                if (tab_mode==2) {      /* list all */
                    char save;
                    p = find_token_end(*avail_p);
                    save = *p;
                    *p = 0;
                    printf("%s ",*avail_p);
                    *p = save;
                    printed += p - *avail_p;
                    if (printed > 70) {
                        printf("\n");
                        printed = 0;
                    }
                }
                else {
                    if (suffix==NULL) { /* first match */
                        suffix = *avail_p+offset;
                        p=find_token_end(suffix);
                        suffix_size = p - suffix;
                    }
                    else {      /* not first match */
                        while ((suffix_size>0) && (strncasecmp(suffix,*avail_p+offset, suffix_size)!=0)) {
                            suffix_size--;
                        }
                    }
                }
            }
        }
    }
    while (suffix_size > 0) {   /* copy suffix to buffer and echo to output (unless too big) */
        process_input_commit_character(*suffix);
        suffix++;
        suffix_size--;
    }
    cmd_pos -= delta_pos;

    if ((tab_mode==2) && printed) printf ("\n");
    process_input_draw_current();
}

void process_input_change_index(int delta)
{
    int new_index = (history_lookup_index+delta) & MAX_HISTORY_MASK;
    int new_cmd_len = strlen(command_history[new_index]);

    if (new_cmd_len == 0) return;       /* ignore if uncharted */
    history_lookup_index = new_index;
    cmd_len = new_cmd_len;
    cmd_pos = cmd_len;

    strcpy(command_history[history_index], command_history[history_lookup_index]);      /* copy to current command */
    process_input_draw_current();
}

static inline void process_input_change_index_to(int line)
{
    process_input_change_index(line - history_lookup_index);
}

static inline void process_input_change_pos(int delta)
{
    cmd_pos += delta;

    if ((signed)cmd_pos < 0) cmd_pos=0;
    if (cmd_pos > cmd_len) cmd_pos=cmd_len;

    process_input_draw_current();
}

static inline void process_input_up()
{
    process_input_change_index(-1);
}

static inline void process_input_down()
{
    process_input_change_index(+1);
}

static inline void process_input_left()
{
    process_input_change_pos(-1);
}

static inline void process_input_right()
{
    process_input_change_pos(+1);
}

static inline void process_input_save_undo()
{
#if DEBUG_ESCAPE
    printf("\nsave_undo: %d, %d, '%s'\n",cmd_len,cmd_pos,cmd);
#endif
    undo.cmd_len = cmd_len;
    undo.cmd_pos = cmd_pos;
    strncpy(undo.cmd, cmd, MAX_COMMAND);
}

static inline void process_input_undo()
{
    undo_t temp;

#if DEBUG_ESCAPE
    printf("\nundo before: %d, %d, '%s'\n",cmd_len,cmd_pos,cmd);
#endif
    temp.cmd_len = undo.cmd_len;
    temp.cmd_pos = undo.cmd_pos;
    strncpy(temp.cmd, undo.cmd, MAX_COMMAND);

    process_input_save_undo();

    cmd_len = temp.cmd_len;
    cmd_pos = temp.cmd_pos;
    strncpy(cmd, temp.cmd, MAX_COMMAND);

#if DEBUG_ESCAPE
    printf("undo after: %d, %d, '%s'\n",cmd_len,cmd_pos,cmd);
#endif
}

static inline void process_input_beginning_of_word()
{
    cmd_pos--;
    while (((signed)cmd_pos >= 0) && (cmd[cmd_pos] == ' ')) {
        cmd_pos--;
    }
    while (((signed)cmd_pos >= 0) && (cmd[cmd_pos] != ' ')) {
        cmd_pos--;
    }
    cmd_pos++;
}

static inline void process_input_next_word()
{
    cmd_pos++;
    while ((cmd_pos < cmd_len) && (cmd[cmd_pos] != ' ')) {
        cmd_pos++;
    }
    while ((cmd_pos < cmd_len) && (cmd[cmd_pos] == ' ')) {
        cmd_pos++;
    }
}

static inline void process_input_clear_line()
{
    printf(ERASE_EOL);
    cmd_len=cmd_pos;
    cmd[cmd_len] = 0;
}

static inline void process_input_delete(unsigned int orig_cmd_pos)
{
    int delta = cmd_pos - orig_cmd_pos;
    int len = cmd_len - cmd_pos + 1;
#if DEBUG_ESCAPE
    printf("<delete: orig %d, new %d, delta %d, len %d>\n",orig_cmd_pos,cmd_pos,delta,len);
#endif
    if (delta < 0) {
        memmove(&cmd[cmd_pos], &cmd[orig_cmd_pos], len);
        cmd_len += delta;
    }
    else if (delta > 0) {
        memmove(&cmd[orig_cmd_pos], &cmd[cmd_pos], len);
        cmd_len -= delta;
        cmd_pos = orig_cmd_pos;
    }
    delete_mode=0;
}

static void process_input(int c)
{
    cmd = command_history[history_index];
    cmd[cmd_len] = 0;

    if (c == 0)         /* no new input */
    {
#ifdef NO_REFRESH
       return; 
#else
        process_input_draw_current();
        goto process_input_done;
#endif
    }

    if (! (escape_mode && !escape_saw_char && !find_mode && (c=='u')) )
        process_input_save_undo();

    if (escape_mode) {  /* process escape sequences */
        if (escape_saw_char == '[') {
            switch (c) {
                case 'A':
                    process_input_up();
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case 'B':
                    process_input_down();
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case 'C':
                    process_input_right();
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case 'D':
                    process_input_left();
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case '\r':
                case '\n':
                    escape_mode=0;
                    escape_saw_char=0;
                    goto parse_input;   /* parse this as a normal character */
                case '2':
                case '3':
                case '5':
                case '6':
                    escape_saw_char=c;  /* really should handle more than one character here */
                    break;
                default:
#if DEBUG_ESCAPE
                    printf("<1:%d,%d(%c)>\n",escape_mode,escape_saw_char,escape_saw_char);
#endif
                    escape_mode=0;
                    escape_saw_char=0;
                    goto parse_input;   /* parse this as a normal character */
            }
        }
        else if (escape_saw_char == 'O') {
            switch (c) {
                case 'H':       /* Home */
                    cmd_pos=0;
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case 'F':       /* End */
                    cmd_pos=cmd_len;
                    escape_mode=0;
                    escape_saw_char=0;
                    break;
                case 'P':       /* F1 */
                    escape_mode=0;
                    escape_saw_char=0;
                    process_command("help");
                    break;
                default:
#if DEBUG_ESCAPE
                    printf("<2:%d,%d(%c)>\n",escape_mode,escape_saw_char,escape_saw_char);
#endif
                    escape_mode=0;
                    escape_saw_char=0;
                    goto parse_input;   /* parse this as a normal character */
            }
        }
        else if (escape_saw_char != 0) {
            if (c == '~') {
                switch (escape_saw_char) {
                    case '2':   /* Insert */
                        insert_mode ^= 1;       /* toggle insert mode */
                        escape_mode=0;
                        escape_saw_char=0;
                        break;
                    case '3':   /* Delete*/
                        process_input_right();  /* translate ESC-x to move right then backspace */
                        c = '\b';
                        escape_mode=0;
                        escape_saw_char=0;
                        goto parse_input;       /* parse this as a normal character */
                    case '5':   /* PageUp */
                    case '6':   /* PageDown */
                        escape_mode=0;  /* ignore for now */
                        escape_saw_char=0;
                        break;
                    default:
#if DEBUG_ESCAPE
                        printf("<3:%d,%d(%c)>\n",escape_mode,escape_saw_char,escape_saw_char);
#endif
                        escape_mode=0;
                        escape_saw_char=0;
                        goto parse_input;       /* parse this as a normal character */
                }
            }
        }
        else {
            unsigned int orig_cmd_pos = cmd_pos;
            switch (c) {        /* parse some vi style escape sequences and arrow keys */
                case 'h':
                    process_input_left();
                    break;
                case 'j':
                    process_input_down();
                    break;
                case 'k':
                    process_input_up();
                    break;
                case '$':
                    cmd_pos=cmd_len;
                    break;
                case '0':
                    cmd_pos=0;
                    break;
                case 'l':
                    process_input_right();
                    break;
                case 'D':
                    process_input_clear_line();
                    break;
                case 'A':
                    cmd_pos=cmd_len;
                    insert_mode=1;
                    escape_mode=0;
                    break;
                case 'a':
                    process_input_right();
                    /* NOTE: fall through */
                case 'i':
                    insert_mode=1;
                    escape_mode=0;
                    break;
                case 'f':
                    find_orig_cmd_pos = cmd_pos;
                    find_mode=1;
                    escape_mode=0;
                    goto process_input_done;    /* skip delete_mode check */
                case 'R':
                    insert_mode=0;
                    escape_mode=0;
                    break;
                case 'b':
                    process_input_beginning_of_word();
                    break;
                case 'w':
                    process_input_next_word();
                    break;
                case 'r':
                    insert_mode=0;
                    escape_mode=0;
                    overwrite_once=1;
                    break;
                case '?':
                case ':':
                case '/':
                    escape_mode=0;
                    cmd_len=0;
                    cmd_pos=0;
                    goto parse_input;   /* parse this as a normal character */
                case '~':
                    if (islower(cmd[cmd_pos])) cmd[cmd_pos] = toupper(cmd[cmd_pos]);
                    else if (isupper(cmd[cmd_pos])) cmd[cmd_pos] = tolower(cmd[cmd_pos]);
                    process_input_right();
                    break;
                case 'c':
                    delete_mode=2;
                    goto process_input_done;    /* skip delete_mode check */
                case 'u':
                    process_input_undo();
                    break;
                case 'd':
                    if (delete_mode==1) {       /* dd is delete line */
                        cmd_len=0;
                        cmd_pos=0;
                        delete_mode=0;
                        break;
                    }
                    delete_mode=1;
                    goto process_input_done;    /* skip delete_mode check */
                case 'x':               /* translate ESC-x to move right then backspace */
                    process_input_right();
                    c = '\b';
                    goto parse_input;   /* parse this as a normal character */
                case 'n':
                    search_mode=1;
                    pattern_dir_reverse = 0;
                    goto search_pattern;
                case 'N':
                    search_mode=1;
                    pattern_dir_reverse = 1;
                    goto search_pattern;
                case '[':
                case 'O':
                    escape_saw_char=c;
                    break;
                case '\r':
                case '\n':
                    escape_mode=0;
                    goto parse_input;   /* parse this as a normal character */
                default:
#if DEBUG_ESCAPE
                    printf("<0:%d,%d(%c)>\n",escape_mode,escape_saw_char,escape_saw_char);
#endif
                    escape_mode=0;
                    escape_saw_char=0;
                    goto parse_input;   /* parse this as a normal character */
            }
            if (delete_mode) {
                if (delete_mode==2) {   /* change mode (delete then insert) */
                    insert_mode=1;
                    escape_mode=0;
                }
                process_input_delete(orig_cmd_pos);
            }
        }
        goto process_input_done;
    }

    if (find_mode) {    /* find a character */
        char *p = strchr(&cmd[cmd_pos],c);
        if ((p!=NULL) && ((p-cmd+1) <= (int)cmd_len)) { /* ignore, not found or beyond range */
            cmd_pos = p-cmd;            /* move to next c */
        }
        find_mode=0;
        escape_mode=1;  /* "stay" in escape mode after find */
        if (delete_mode) {
            cmd_pos++;  /* also delete found character in find mode */
            if (cmd_pos > cmd_len) cmd_pos=cmd_len;
            process_input_delete(find_orig_cmd_pos);
        }
        goto process_input_done;
    }

parse_input:
    if (overwrite_once) {
        escape_mode=1;
        overwrite_once=0;
    }
    if ((c == '\t') || (c == '\x04'))   /* tab completion, scan help strings for completion possibilities */
    {
        char *token_start;

        SET_SCROLL_REGION(max_displayed_row);
        process_input_draw_current();

        if (c == '\x04') tab_mode=2;    /* list all possibilities */
        if (tab_mode==0) {
            saved_avail_p=NULL;         /* start over */
            saved_suffix_size=0;        /* start over */
        }
        cmd[cmd_len] = 0;
        token_start = &cmd[cmd_pos] - (cmd_pos != 0);
        while ((token_start > cmd) && (*token_start != ' ')) token_start--;
        if (token_start==cmd) {         /* first token of command */
            tab_complete(cmd, help_commands);
        }
        else {
            token_start++;      /* skip space */
            secondary_lut_lut_t *second;
            for (second = secondary_lut_lut; second->command; second++) {
                if (strncasecmp(cmd,second->command,strlen(second->command))==0) {
                    tab_complete(token_start, second->lut);
                    break;
                }
            }
        }
        if (tab_mode==2)
            tab_mode=0;
        else
            tab_mode=1;
    }
    else if ((tab_mode==1) && (c==' ')) {       /* space after multi-tab selects and moves to next space or end */
        char *p = strchr(&cmd[cmd_pos],' ');
        if ((p==NULL) || ((p-cmd+1) > (int)cmd_len)) {
            cmd_pos = cmd_len;          /* move to end of command */
        }
        else {
            cmd_pos = p-cmd+1;          /* move to just after next space */
        }
    }
    else if ((tab_mode=0)) {    /* NOTE: always false, but used to clear tab mode and keep "else if" strucure clean */
        /* never happens */
    }
    else if (c=='\033') {       /* escape character */
        escape_mode=1;
    }
    else if ((c>=32) && (c<=126))       /* normal character */
    {
        process_input_commit_character(c);
    }
    else if (c == '\x0c')       /* control-l erases/redraws sreeen */
    {
        printf(GOTO_TOP ERASE_EOS);
    }
    else if (c == '\b')         /* backspace */
    {
        if (cmd_pos)
        {
            cmd_len--;
            cmd_pos--;
            if (cmd_pos < cmd_len) {
                memmove(&cmd[cmd_pos], &cmd[cmd_pos+1], cmd_len-cmd_pos+1);
            }
        }
    }
    else if ((c == '\r') || (c == '\n'))        /* CR/LF */
    {
        static int was_lookup = 0;

        was_lookup = (cmd[0] == '/') || (cmd[0] == '?') || (cmd[0] == ':');
        search_mode = (cmd[0] == '/') || (cmd[0] == '?');
        if (help_frozen) {
            printf(GOTO_TOP ERASE_EOS);
            help_frozen = 0;
        }
        cmd[cmd_len] = 0;
        cmd_pos = cmd_len;
        if ((cmd[0] == '!') || was_lookup) {
            int new_line;
            if ((cmd[1] == '!') || (cmd[1] == ':')) {
                process_input_change_index_to(history_index-1);
            }
            else if ((!search_mode) && (sscanf(cmd+1,"%d",&new_line)==1)) {
                process_input_change_index_to(new_line);
            }
            else {      /* search for first line starting with !pat */
                int len;
                int delta;
                strcpy(pattern,cmd+1);
                pattern_dir_delta = (cmd[0] == '/') ? 1 : -1;
                pattern_dir_reverse=0;
search_pattern:
                delta = pattern_dir_delta;
                if (pattern_dir_reverse) {
                    if (pattern_dir_delta == 1) delta= -1;
                    else delta = 1;
                }
                else if (delta == 0) delta = -1;        /* just in case.... */

                len=strlen(pattern);
#define PREV_HIST(x) ( ((x)+delta) & MAX_HISTORY_MASK )
                for (new_line=PREV_HIST(history_lookup_index);
                        (command_history[new_line][0]) && (new_line!=history_lookup_index);
                        new_line=PREV_HIST(new_line)) {
                    if (search_mode) {  /* search anywhere, NOTE case sensitive */
                        if (strstr(command_history[new_line],pattern)!=0) {
                            process_input_change_index_to(new_line);
                            break;
                        }
                    }
                    else {      /* only search from beginning, case insensitive */
                        if (strncasecmp(pattern,command_history[new_line],len)==0) {
                            process_input_change_index_to(new_line);
                            break;
                        }
                    }
                }
            }
        }
        process_input_draw_current();
        if (!(was_lookup || search_mode)) {     /* don't execute if only a lookup */
            if (cmd_len != 0) history_index = (history_index + 1) & MAX_HISTORY_MASK;
            history_lookup_index = history_index;
            process_command(cmd);
            cmd_len = 0;
            cmd_pos = 0;
        }
        else {
            escape_mode=1;      /* "stay" in escape mode after search */
            search_mode=0;
        }
    }
process_input_done:
    printf(CURSOR_OFF SCROLL_FULL GOTO_BOTTOM CURSOR_ON);       /* in case we stop here */
    process_input_draw_current();
}

void cli(void)
{
#ifdef ENABLE_PCI_COMMAND
    volatile uint32_t *bootloader_pci_owner = cvmx_phys_to_ptr(BOOTLOADER_PCI_READ_BUFFER_OWNER_ADDR);
    volatile uint32_t *bootloader_pci_len = cvmx_phys_to_ptr(BOOTLOADER_PCI_READ_BUFFER_LEN_ADDR);
    char *bootloader_pci_addr = cvmx_phys_to_ptr(BOOTLOADER_PCI_READ_BUFFER_DATA_ADDR);
#endif
    cvmx_sysinfo_t *sysinfo;
    uint64_t i, delay_count = 100000000;

    sysinfo = cvmx_sysinfo_get();
    cpu_clock_hz = sysinfo->cpu_clock_hz;
    cvmx_uart_mcr_t mcr;
    mcr.u64 = cvmx_read_csr(CVMX_MIO_UARTX_MCR(0));
    mcr.s.afce = 1;
    cvmx_write_csr(CVMX_MIO_UARTX_MCR(0), mcr.u64);

    printf(ERASE_WIN); /* Erase the window */

    // swings dbg_select to the CSR rather than the pins
    cvmx_write_csr(CVMX_DBG_DATA, 0);
#ifdef ENABLE_PCI_COMMAND
    *bootloader_pci_owner = OCTEON_PCI_IO_BUF_OWNER_HOST;
#endif
    for(i=0;i<delay_count;i++) {
	;
    }
    for(i=0;i<delay_count;i++) {
	;
    }

    printf("\n\n\n");
    printf("Initializing Octeon Command Line Interface on core %d\n\n", (int)cvmx_get_core_num());
    printf("Octeon command line interface ver 1.0\n\n");
    printf("Command line interface is now ready\n\n");
    printf("Please type 'help' for the list of commands\n");

    uint64_t update_time = cvmx_get_cycle();

    while (1)
    {
        process_input(0);

        /* Wait a second so the status gives per second rates */
        do
        {
#ifdef ENABLE_PCI_COMMAND
            if (*bootloader_pci_owner == OCTEON_PCI_IO_BUF_OWNER_OCTEON)
            {
                bootloader_pci_addr[*bootloader_pci_len] = 0;
                printf("[PCI] %s", bootloader_pci_addr);
                process_command(bootloader_pci_addr);
                *bootloader_pci_owner = OCTEON_PCI_IO_BUF_OWNER_HOST;
                process_input(0);
            }
#endif
            int c = uart_read_byte(0);
            if (c)
                process_input(c);
            else
                cvmx_wait(1000); /* Just to reduce the load on the system */
        }
        while (cvmx_get_cycle() < update_time);
        update_time += cpu_clock_hz;
   }
}

unsigned int dump_elf_info(unsigned char st_type)
{
   Elf32_Ehdr *ehdr;               /* Elf header structure pointer     */
   Elf32_Shdr *shdr = NULL;        /* Section header structure pointer */
   unsigned char *strtab = 0;      /* String table pointer             */
   int i;                     /* Loop counter                     */
   Elf32_Sym  *sym;
   unsigned long addr = ELF_BASE_ADDR;
   uint64_t nsymbols, j=0;
                                                                                                                                                                                       
   ehdr = (Elf32_Ehdr *) addr;
                                                                                                                                                                                       
   for (i = 0; i < ehdr->e_shnum; ++i) {
      /* Find the section header string table for output info */
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                                      (i * sizeof (Elf32_Shdr)));
                                                                                                                                                                                       
      if (shdr->sh_type == SHT_STRTAB) {
         if(j == 1) {
            strtab = (unsigned char *) (addr + shdr->sh_offset);
            j = 2;
         }
         else {
            j = 1;
         }
      }
   }
                                                                                                                                                                                       
   if(j != 2) {
      printf("String table not found. Please make sure the NON STRIPPED elf file is loaded at 0x%lx\n", addr);
      return -1;
   }
                                                                                                                                                                                       
   /* Load each appropriate section */
   for (i = 0; i < ehdr->e_shnum; ++i) {
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                             (i * sizeof (Elf32_Shdr)));
                                                                                                                                                                                       
      if(shdr->sh_type == SHT_SYMTAB)
         break;
   }
                                                                                                                                                                                       
   nsymbols = shdr->sh_size/shdr->sh_entsize;
               
   for(j=0;j<nsymbols;j++) {
     sym = (Elf32_Sym *) ((unsigned char *) addr + (shdr->sh_offset + (j * sizeof(Elf32_Sym))));

     if(st_type == (sym->st_info & 0xf)) {
	  printf("%s\n", &strtab[sym->st_name]);
     }
   }
   return 0;
}

char* get_func_name(char* func_name, unsigned int func_addr)
{
   Elf32_Ehdr *ehdr;               /* Elf header structure pointer     */
   Elf32_Shdr *shdr = NULL;        /* Section header structure pointer */
   unsigned char *strtab = 0;      /* String table pointer             */
   int i;                     /* Loop counter                     */
   Elf32_Sym  *sym;
   unsigned long addr = ELF_BASE_ADDR;
   uint64_t nsymbols, j=0;

   ehdr = (Elf32_Ehdr *) addr;
  
   for (i = 0; i < ehdr->e_shnum; ++i) { 
      /* Find the section header string table for output info */
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                                      (i * sizeof (Elf32_Shdr)));

      if (shdr->sh_type == SHT_STRTAB) {
	 if(j == 1) {
            strtab = (unsigned char *) (addr + shdr->sh_offset);
            j = 2;
	 }
	 else {
	    j = 1;
	 }
      }
   }
 
   if(j != 2) {
      printf("String table not found. Please make sure the NON STRIPPED elf file is loaded at 0x%lx\n", addr);
      return 0;
   }

   /* Load each appropriate section */
   for (i = 0; i < ehdr->e_shnum; ++i) {
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                             (i * sizeof (Elf32_Shdr)));
                                                                                                                                            
      if(shdr->sh_type == SHT_SYMTAB)
	 break;
   }
  
   nsymbols = shdr->sh_size/shdr->sh_entsize;

   for(j=0;j<nsymbols;j++) {
     sym = (Elf32_Sym *) ((unsigned char *) addr + (shdr->sh_offset + (j * sizeof(Elf32_Sym))));

     if(((sym->st_info & 0xf) == STT_FUNC) && (func_addr == sym->st_value)) {
       strcpy( (char*)func_name, (char*)&strtab[sym->st_name]);
     }
   }

     return func_name;
} 

void lookup_str(char *str, unsigned char st_type)
{
   Elf32_Ehdr *ehdr;               /* Elf header structure pointer     */
   Elf32_Shdr *shdr = NULL;        /* Section header structure pointer */
   unsigned char *strtab = 0;      /* String table pointer             */
   int i;                     /* Loop counter                     */
   Elf32_Sym  *sym;
   unsigned long addr = ELF_BASE_ADDR;
   uint64_t nsymbols, j=0;
   uint16_t str_len, sym_len;
   char *sym_str;
                                                                                                                                                    
   ehdr = (Elf32_Ehdr *) addr;
                                                                                                                                                    
   for (i = 0; i < ehdr->e_shnum; ++i) {
      /* Find the section header string table for output info */
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                                      (i * sizeof (Elf32_Shdr)));
                                                                                                                                                    
      if (shdr->sh_type == SHT_STRTAB) {
         if(j == 1) {
            strtab = (unsigned char *) (addr + shdr->sh_offset);
            j = 2;
         }
         else {
            j = 1;
         }
      }
   }
                                                                                                                                                    
   if(j != 2) {
      printf("String table not found. Please make sure the NON STRIPPED elf file is loaded at 0x%lx\n", addr);
      return;
   }
                                                                                                                                                    
   /* Load each appropriate section */
   for (i = 0; i < ehdr->e_shnum; ++i) {
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                             (i * sizeof (Elf32_Shdr)));
                                                                                                                                                    
      if(shdr->sh_type == SHT_SYMTAB)
         break;
   }
                                                                                                                                                    
   nsymbols = shdr->sh_size/shdr->sh_entsize;
   str_len = strlen(str);
                                                                                                                                                    
   for(j=0;j<nsymbols;j++) {
     sym = (Elf32_Sym *) ((unsigned char *) addr + (shdr->sh_offset + (j * sizeof(Elf32_Sym))));
                                                                                                                                                    
     if((sym->st_info & 0xf) == st_type) {
          sym_len = strlen((const char*)&strtab[sym->st_name]);
          sym_str =  (char*)&strtab[sym->st_name];
          i=0;
          while(sym_len >= str_len) {
              if(memcmp(str, sym_str, str_len) == 0) {
                 printf("%s\n", &strtab[sym->st_name]);
                 break;
              }
              sym_str++;
              sym_len--;
          }
     }
   }
   return;
}

unsigned int exec_command(char *command, argument_info_t *args, int argc)
{
   Elf32_Ehdr *ehdr;               /* Elf header structure pointer     */
   Elf32_Shdr *shdr = NULL;        /* Section header structure pointer */
   unsigned char *strtab = 0;      /* String table pointer             */
   int i;                     /* Loop counter                     */
   Elf32_Sym  *sym;
   unsigned long addr = ELF_BASE_ADDR;
   uint64_t rc = 0;
   uint64_t nsymbols, j=0;

   ehdr = (Elf32_Ehdr *) addr;
  
   for (i = 0; i < ehdr->e_shnum; ++i) { 
      /* Find the section header string table for output info */
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                                      (i * sizeof (Elf32_Shdr)));

      if (shdr->sh_type == SHT_STRTAB) {
	 if(j == 1) {
            strtab = (unsigned char *) (addr + shdr->sh_offset);
            j = 2;
	 }
	 else {
	    j = 1;
	 }
      }
   }
 
   if(j != 2) {
      printf("String table not found. Please make sure the NON STRIPPED elf file is loaded at 0x%lx\n", addr);
      return -1;
   }

   /* Load each appropriate section */
   for (i = 0; i < ehdr->e_shnum; ++i) {
      shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
                             (i * sizeof (Elf32_Shdr)));
                                                                                                                                            
      if(shdr->sh_type == SHT_SYMTAB)
	 break;
   }
  
   nsymbols = shdr->sh_size/shdr->sh_entsize;

   for(j=0;j<nsymbols;j++) {
     sym = (Elf32_Sym *) ((unsigned char *) addr + (shdr->sh_offset + (j * sizeof(Elf32_Sym))));

     if(((sym->st_info & 0xf) == STT_FUNC) && (strcmp(command, (const char*)&strtab[sym->st_name]) == 0)) {
	   addr = sym->st_value;
	   switch((argc-1))
           {
		case 0:
			rc = ((unsigned long (*)()) addr) ();
			break;
		case 1:
			rc = ((unsigned long (*)(unsigned long)) addr) (args[1].number);
			break;

		case 2:
			rc = ((unsigned long (*)(unsigned long, unsigned long)) addr) (args[1].number, 
											args[2].number);
			break;

		case 3:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long)) addr) (args[1].number, 
											args[2].number, args[3].number);
			break;

		case 4:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long)) addr) 
							(args[1].number, args[2].number, args[3].number, args[4].number);
			break;
		case 5:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long)) 
							addr) (args[1].number, args[2].number, args[3].number, args[4].number, 
							args[5].number);
			break;
		case 6:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long,
							unsigned long)) addr) (args[1].number, args[2].number, args[3].number, 
							args[4].number, args[5].number, args[6].number);
			break;
		case 7:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, 
							unsigned long, unsigned long)) addr) (args[1].number, args[2].number, 
							args[3].number, args[4].number, args[5].number, args[6].number, 
							args[7].number);
			break;
		case 8:
			rc = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, 
							unsigned long, unsigned long, unsigned long)) addr) (args[1].number, 
							args[2].number, args[3].number, args[4].number, args[5].number, 
							args[6].number, args[7].number, args[8].number);
			break;
	   }
	   printf("return = 0x%llx\n", CAST64(rc) );
	   return 0;
     }
     else if(((sym->st_info & 0x0f) == STT_OBJECT) && (strcmp(command, (const char*)&strtab[sym->st_name]) == 0)) {
	addr = sym->st_value;
	if(*(char *)(&args[1].str) == '=') {
		*((uint64_t *)addr) = args[2].number;
	}
	else {
	  printf("%s = 0x%llx\n", &strtab[sym->st_name], CAST64(*((uint64_t *)addr)) );
        }
	return 0;
     }
  }
   printf("Symbol not found\n");
   return 0;
}
