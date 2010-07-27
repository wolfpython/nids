/*
 ** Copyright (C) 1998-2010 Sourcefire, Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* sp_file_data
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "bounds.h"
#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"

#include "snort.h"
#include "profiler.h"
#include "sp_isdataat.h"
#ifdef PERF_PROFILING
PreprocStats fileDataPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#include "detection_options.h"

extern char *file_name;  /* this is the file name from rules.c, generally used
                            for error messages */

extern int file_line;    /* this is the file line number from rules.c that is
                            used to indicate file lines for error messages */
extern const u_char *file_data_ptr;

extern const uint8_t *doe_ptr;

void FileDataInit(char *, OptTreeNode *, int);
void FileDataParse(char *, OptTreeNode *);
int  FileDataEval(void *option_data, Packet *p);

/****************************************************************************
 * 
 * Function: SetupFileData()
 *
 * Purpose: Load 'er up
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupFileData(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterRuleOption("file_data", FileDataInit, NULL, OPT_TYPE_DETECTION, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("file_data", &fileDataPerfStats, 3, &ruleOTNEvalPerfStats);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: file_data Setup\n"););
}

static INLINE int IsEmptyStr(char *str)
{
    char *end;

    if (str == NULL)
        return 1;

    end = str + strlen(str);

    while ((str < end) && isspace((int)*str))
        str++;

    if (str == end)
        return 1;

    return 0;
}



/****************************************************************************
 * 
 * Function: FileDataInit(char *, OptTreeNode *, int protocol)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *            protocol => protocol the rule is on (we don't care in this case)
 *
 * Returns: void function
 *
 ****************************************************************************/
void FileDataInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;

    FileDataParse(data, otn);

    fpl = AddOptFuncToList(FileDataEval, otn);
    fpl->type = RULE_OPTION_TYPE_FILE_DATA;
    
}



/****************************************************************************
 * 
 * Function: FileDataParse(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void FileDataParse(char *data, OptTreeNode *otn)
{
    if (!IsEmptyStr(data))
    {
        FatalError("%s(%d): file_data takes no arguments\n",
                                file_name, file_line);
    }

}


/****************************************************************************
 * 
 * Function: FileDataEval(char *, OptTreeNode *, OptFpList *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: p => pointer to the decoded packet
 *            otn => pointer to the current rule's OTN
 *            fp_list => pointer to the function pointer list
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
int FileDataEval(void *option_data, Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    PREPROC_PROFILE_START(fileDataPerfStats);

    if ((p->dsize == 0) || (!IsTCP(p) && !IsUDP(p)) || (file_data_ptr == NULL))
    {
        PREPROC_PROFILE_END(fileDataPerfStats);
        return rval;
    }


    doe_ptr = file_data_ptr;
    rval = DETECTION_OPTION_MATCH;

    PREPROC_PROFILE_END(fileDataPerfStats);
    return rval;
}
