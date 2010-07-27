/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2010 Sourcefire, Inc.
 *
 * Author: Steven Sturges
 *
 * Dynamic Library Loading for Snort
 *
 */
#ifndef _SF_DYNAMIC_ENGINE_H_
#define _SF_DYNAMIC_ENGINE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef WIN32
#include <sys/types.h>
#else
#include <stdint.h>
#endif

#include "sf_dynamic_define.h"
#include "sf_dynamic_meta.h"
#include "sf_types.h"

/* specifies that a function does not return 
 * used for quieting Visual Studio warnings
 */
#ifdef WIN32
#if _MSC_VER >= 1400
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#else
#define NORETURN
#endif

/* Function prototype used to evaluate a special OTN */
typedef int (*OTNCheckFunction)(void* pPacket, void* pRule);

/* flowFlag is FLOW_*; check flowFlag iff non-zero */
typedef int (*OTNHasFunction)(void* pRule, DynamicOptionType, int flowFlag);

/* Data struct & function prototype used to get list of
 * Fast Pattern Content information. */
typedef struct _FPContentInfo
{
    char *content;
    int length;
    int offset;
    int depth;
    char noCaseFlag;
    char exception_flag;
    char is_relative;
    char fp;
    char fp_only;
    u_int16_t fp_offset;
    u_int16_t fp_length;
    struct _FPContentInfo *next;

} FPContentInfo;

/* Parameters are rule info pointer, int to indicate URI or NORM,
 * and list pointer */
#define CONTENT_NORMAL            0x01
#define CONTENT_HTTP_URI          0x02
#define CONTENT_HTTP_HEADER       0x04
#define CONTENT_HTTP_CLIENT_BODY  0x08
#define CONTENT_HTTP_METHOD       0x10
#define CONTENT_HTTP (CONTENT_HTTP_URI|CONTENT_HTTP_HEADER|\
        CONTENT_HTTP_CLIENT_BODY|CONTENT_HTTP_METHOD)
typedef int (*GetDynamicContentsFunction)(void *, int, FPContentInfo **);
typedef int (*GetDynamicPreprocOptFpContentsFunc)(void *, FPContentInfo **);
typedef void (*RuleFreeFunc)(void *);

/* ruleInfo is passed to OTNCheckFunction when the fast pattern matches. */
typedef int (*RegisterRule)(
    u_int32_t, u_int32_t, void *,
    OTNCheckFunction, OTNHasFunction,
    int, GetDynamicContentsFunction, RuleFreeFunc,
    GetDynamicPreprocOptFpContentsFunc
);
typedef u_int32_t (*RegisterBit)(char *, int);
typedef int (*CheckFlowbit)(void *, int, u_int32_t);
typedef int (*DetectAsn1)(void *, void *, const u_int8_t *);
typedef int (*PreprocOptionEval)(void *p, const u_int8_t **cursor, void *dataPtr);
typedef int (*PreprocOptionInit)(char *, char *, void **dataPtr);
typedef void (*PreprocOptionCleanup)(void *dataPtr);
#define PREPROC_OPT_EQUAL       0
#define PREPROC_OPT_NOT_EQUAL   1
typedef u_int32_t (*PreprocOptionHash)(void *);
typedef int (*PreprocOptionKeyCompare)(void *, void *);
/* Function prototype for rule options that want to add patterns to the
 * fast pattern matcher */
typedef int (*PreprocOptionFastPatternFunc)
    (void *rule_opt_data, int protocol, int direction, FPContentInfo **info);
typedef int (*PreprocOptionOtnHandler)(void *);

typedef int (*RegisterPreprocRuleOpt)(
    char *, PreprocOptionInit, PreprocOptionEval,
    PreprocOptionCleanup, PreprocOptionHash, PreprocOptionKeyCompare,
    PreprocOptionOtnHandler, PreprocOptionFastPatternFunc);
typedef int (*PreprocRuleOptInit)(void *);

typedef void (*SetRuleData)(void *, void *);
typedef void *(*GetRuleData)(void *);

/* Info Data passed to dynamic engine plugin must include:
 * version
 * Pointer to AltDecodeBuffer
 * Pointer to HTTP URI Buffers
 * Pointer to function to register C Rule
 * Pointer to function to register C Rule flowbits
 * Pointer to function to check flowbit
 * Pointer to function to do ASN1 Detection
 * Pointer to functions to log Messages, Errors, Fatal Errors
 * Directory path
 */
#include "sf_dynamic_common.h"

#define ENGINE_DATA_VERSION 5

typedef void *(*PCRECompileFunc)(const char *, int, const char **, int *, const unsigned char *);
typedef void *(*PCREStudyFunc)(const void *, int, const char **);
typedef int (*PCREExecFunc)(const void *, const void *, const char *, int, int, int, int *, int);

typedef struct _DynamicEngineData
{
    int version;
    u_int8_t *altBuffer;
    UriInfo *uriBuffers[MAX_URIINFOS];
    RegisterRule ruleRegister;
    RegisterBit flowbitRegister;
    CheckFlowbit flowbitCheck;
    DetectAsn1 asn1Detect;
    LogMsgFunc logMsg;
    LogMsgFunc errMsg;
    LogMsgFunc fatalMsg;
    char *dataDumpDirectory;

    PreprocRuleOptInit preprocRuleOptInit;

    SetRuleData setRuleData;
    GetRuleData getRuleData;

    DebugMsgFunc debugMsg;
#ifdef HAVE_WCHAR_H
    DebugWideMsgFunc debugWideMsg;
#endif

    char **debugMsgFile;
    int *debugMsgLine;

    PCRECompileFunc pcreCompile;
    PCREStudyFunc pcreStudy;
    PCREExecFunc pcreExec;

} DynamicEngineData;

/* Function prototypes for Dynamic Engine Plugins */
void CloseDynamicEngineLibs(void);
void LoadAllDynamicEngineLibs(char *path);
int LoadDynamicEngineLib(char *library_name, int indent);
typedef int (*InitEngineLibFunc)(DynamicEngineData *);
typedef int (*CompatibilityFunc)(DynamicPluginMeta *meta, DynamicPluginMeta *lib);

int InitDynamicEngines(char *);
void RemoveDuplicateEngines(void);
int DumpDetectionLibRules(void);
int ValidateDynamicEngines(void);

/* This was necessary because of static code analysis not recognizing that
 * fatalMsg did not return - use instead of fatalMsg
 */
NORETURN void DynamicEngineFatalMessage(const char *format, ...);

typedef struct _PreprocessorOptionInfo
{
    PreprocOptionInit optionInit;
    PreprocOptionEval optionEval;
    PreprocOptionCleanup optionCleanup;
    void             *data;
    PreprocOptionHash optionHash;
    PreprocOptionKeyCompare optionKeyCompare;
    PreprocOptionOtnHandler otnHandler;
    PreprocOptionFastPatternFunc optionFpFunc;

} PreprocessorOptionInfo;

#endif /* _SF_DYNAMIC_ENGINE_H_ */
