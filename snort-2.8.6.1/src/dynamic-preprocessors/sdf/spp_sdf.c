/*
** Copyright (C) 2009-2010 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

/*
#include "snort.h"
#include "parser.h"
#include "util.h"
#include "plugbase.h"
*/
#include "debug.h"
#include "stream_api.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include "sf_snort_packet.h"

/*
#ifdef TARGET_BASED
#include "sftarget_protocol_reference.h"
#endif
*/

#include "profiler.h"

#include "spp_sdf.h"
#include "sdf_us_ssn.h"
#include "sdf_detection_option.h"
#include "sdf_pattern_match.h"

extern DynamicPreprocessorData _dpd;

/* PROTOTYPES */
static void SDFInit(char *args);
static void ProcessSDF(void *p, void *context);
static SDFConfig * NewSDFConfig(tSfPolicyUserContextId);
static void ParseSDFArgs(SDFConfig *config, char *args);
static void SDFCleanExit(int signal, void *unused);
static int SDFFreeConfig(tSfPolicyUserContextId context, tSfPolicyId id, void *pData);
static void SDFFillPacket(sdf_tree_node *node, SDFSessionData *session,
                          SFSnortPacket *p, uint16_t *dlen);
static void SDFPrintPseudoPacket(SDFConfig *config, SDFSessionData *session,
                                 SFSnortPacket *real_packet);

#ifdef SNORT_RELOAD
static void SDFReload(char *);
static void * SDFReloadSwap(void);
static void SDFReloadSwapFree(void *);
#endif

/* GLOBALS :( */
sdf_tree_node *head_node = NULL;
uint32_t num_patterns = 0;
tSfPolicyUserContextId sdf_context_id = NULL;

#ifdef SNORT_RELOAD
sdf_tree_node *swap_head_node = NULL;
uint32_t swap_num_patterns = 0;
tSfPolicyUserContextId sdf_swap_context_id = NULL;
#endif

#ifdef PERF_PROFILING
PreprocStats sdfPerfStats;
#endif

/*
 * Function: SetupSDF()
 *
 * Purpose: Registers the preprocessor keyword and initialization function
 *          into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void
 *
 */
void SetupSDF(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("sensitive_data", SDFInit);
#else
    _dpd.registerPreproc("sensitive_data", SDFInit, SDFReload, SDFReloadSwap, 
                         SDFReloadSwapFree);
#endif
}

/*
 * Function: SDFInit(char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the port list,
 *          links the processing function into the preproc function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void
 *
 */
void SDFInit(char *args)
{
    SDFConfig *config = NULL;

    /* Check prerequisites */
    if (_dpd.streamAPI == NULL)
    {
        DynamicPreprocessorFatalMessage("SDFInit(): The Stream preprocessor must be enabled.\n");
    }

    /* Create context id, register callbacks. This is only done once. */
    if (sdf_context_id == NULL)
    {
        sdf_context_id = sfPolicyConfigCreate();
        /* Allocate the head of the pattern-matching tree */
        head_node = (sdf_tree_node *)calloc(1, sizeof(sdf_tree_node));
        if (!head_node)
            DynamicPreprocessorFatalMessage("Failed to allocate memory for SDF "
                                            "configuration.\n");

        _dpd.addPreprocExit(SDFCleanExit, NULL, PRIORITY_LAST, PP_SDF);
        _dpd.addPreprocRestart(SDFCleanExit, NULL, PRIORITY_LAST, PP_SDF);

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("sensitive_data", (void *)&sdfPerfStats, 0, _dpd.totalPerfStats);
#endif
    }

    /* Handle configuration. This is done once for each policy. */
    config = NewSDFConfig(sdf_context_id);
    ParseSDFArgs(config, args);

    /* Register callbacks */
    _dpd.addPreproc(ProcessSDF, PRIORITY_LAST, PP_SDF,
                    PROTO_BIT__TCP | PROTO_BIT__UDP);
    _dpd.preprocOptRegister(SDF_OPTION_NAME, SDFOptionInit, SDFOptionEval,
                            NULL, NULL, NULL, SDFOtnHandler, NULL);
}


/* Check the ports and target-based protocol for a given packet.
 *
 * Returns: 0 if the port check fails
 *          1 if the packet should be inspected
 */
static int SDFCheckPorts(SDFConfig *config, SFSnortPacket *packet)
{
    int16_t app_ordinal = SFTARGET_UNKNOWN_PROTOCOL;

    /* Do port checks */
#ifdef TARGET_BASED
    app_ordinal = _dpd.streamAPI->get_application_protocol_id(packet->stream_session_ptr);
    if (app_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
        return 0;
    if (app_ordinal && (config->protocol_ordinals[app_ordinal] == 0))
        return 0;
    if (app_ordinal == 0)
    {
#endif
        /* No target-based info for this packet. Check ports. */
        if (((config->src_ports[PORT_INDEX(packet->src_port)] & CONV_PORT(packet->src_port)) == 0) &&
            ((config->dst_ports[PORT_INDEX(packet->dst_port)] & CONV_PORT(packet->dst_port)) == 0))
        {
            return 0;
        }
#ifdef TARGET_BASED
    }
#endif

    return 1;
}

/* A free function that gets registered along with our Stream session data */
static void FreeSDFSession(void *data)
{
    SDFSessionData *session = (SDFSessionData *)data;

    if (session == NULL)
        return;

    free(session->counters);
    free(session->rtns_matched);
    free(session);
    return;
}

/* Create a new SDF session data struct.
   Returns:
      Fatal Error if allocation fails
      Valid ptr otherwise
*/
static SDFSessionData * NewSDFSession(SDFConfig *config, SFSnortPacket *packet)
{
    SDFSessionData *session;

    /* Allocate new session data. */
    session = (SDFSessionData *) calloc(1, sizeof(SDFSessionData));
    if (session == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                "SDF preprocessor session data.\n");
    }

    if (packet->stream_session_ptr)
    {
        _dpd.streamAPI->set_application_data(packet->stream_session_ptr,
                                             PP_SDF, session, FreeSDFSession);
    }

    /* Allocate counters in the session data */
    session->num_patterns = num_patterns;
    session->counters = calloc(session->num_patterns, sizeof(uint8_t));
    session->rtns_matched = calloc(session->num_patterns, sizeof(int8_t));
    if (session->counters == NULL || session->rtns_matched == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for "
                "SDF preprocessor session data.\n");
    }

    return session;
}

/* Search a buffer for PII. Generates alerts when enough PII is found.
   Returns: void
*/
static void SDFSearch(SDFConfig *config, SFSnortPacket *packet,
                      SDFSessionData *session, char *position, char *end,
                      uint16_t buflen)
{
    while (position < end)
    {
        uint16_t match_length = 0;
        int index;
        SDFOptionData *found_pattern = NULL;

        /* Traverse the pattern tree and match PII against our data */
        found_pattern = FindPii(head_node, position, &match_length,
                                buflen, config);

        if (found_pattern)
            index = found_pattern->counter_index;

        /* Check the RTN for the PII we found. The IPs & ports might not match.
           We only want to do this once per session */
        if (found_pattern &&
            session->rtns_matched[index] == 0)
        {
            int check_ports = 1;
            OptTreeNode *otn = found_pattern->otn;
            RuleTreeNode *rtn = NULL;
#ifdef TARGET_BASED
            uint16_t app_ordinal;
            unsigned int i;
#endif

            if (_dpd.getRuntimePolicy() < otn->proto_node_num)
                rtn = otn->proto_nodes[_dpd.getRuntimePolicy()];

#ifdef TARGET_BASED
            /* Check the service against the matched OTN. */
            app_ordinal = _dpd.streamAPI->get_application_protocol_id(packet->stream_session_ptr);
            for (i = 0; i < otn->sigInfo.num_services; i++)
            {
                if (otn->sigInfo.services[i].service_ordinal == app_ordinal)
                    check_ports = 0;
            }
#endif
            if (rtn != NULL && _dpd.fpEvalRTN(rtn, packet, check_ports))
                session->rtns_matched[index] = 1;
            else
                session->rtns_matched[index] = -1;
        }

        if (found_pattern && session->rtns_matched[index] == 1)
        {
            /* Increment counters */
            session->global_counter++;
            session->counters[found_pattern->counter_index]++;

            /* Obfuscate the data.
               We do this even if it's not time to alert, to obfuscate each match. */
            if (config->mask_output)
            {
                uint16_t offset, ob_length = 0;

                /* Only obfuscate built-in patterns */
                if (found_pattern->validate_func)
                {
                    offset = (uint16_t) (position - (char *)packet->payload);

                    if (match_length > SDF_OBFUSCATION_DIGITS_SHOWN)
                        ob_length = match_length - SDF_OBFUSCATION_DIGITS_SHOWN;

                    _dpd.obApi->addObfuscationEntry(packet, offset, ob_length,
                                                    SDF_OBFUSCATION_CHAR);
                }
            }

            /* Check the counters and alert */
            if (session->global_counter == config->threshold)
            {
                /* Do our "combo alert" */
                SDFPrintPseudoPacket(config, session, packet);
                _dpd.genSnortEvent(config->pseudo_packet,
                                   GENERATOR_SPP_SDF_PREPROC,
                                   SDF_COMBO_ALERT_SID,
                                   SDF_COMBO_ALERT_REV,
                                   SDF_COMBO_ALERT_CLASS,
                                   SDF_COMBO_ALERT_PRIORITY,
                                   SDF_COMBO_ALERT_STR);
            }
            if (session->counters[found_pattern->counter_index] == found_pattern->count)
            {
                
                /* Raise the alert for this particular pattern */
                _dpd.alertAdd(GENERATOR_SPP_SDF_RULES,
                              found_pattern->otn->sigInfo.id,
                              found_pattern->otn->sigInfo.rev,
                              found_pattern->otn->sigInfo.class_id,
                              found_pattern->otn->sigInfo.priority,
                              found_pattern->otn->sigInfo.message,
                              0);
            }

            position += match_length;
            buflen -= match_length;
        }
        else
        {
            position++;
            buflen--;
        }
    }
}

/*
 * Function: ProcessSDF(void *, void *)
 *
 * Purpose: Inspects a packet's payload for Personally Identifiable Information
 *
 * Arguments: p => poitner to the current packet data struct
 *            context => unused void pointer
 *
 * Returns: void
 *
 */
static void ProcessSDF(void *p, void *context)
{
    tSfPolicyId policy_id;
    SDFConfig *config = NULL;
    SFSnortPacket *packet = (SFSnortPacket *)p;
    SDFSessionData *session;
    char *begin, *end;
    u_int16_t buflen;
    PROFILE_VARS;

    /* Check if we should be working on this packet */
    if (( !packet ) ||                                      // No packet
        ( !packet->payload ) ||                             // No data
        ( !packet->payload_size ) ||                        // No data size
        ( !IPH_IS_VALID(packet) ) ||                        // Invalid IP Header
        ( !packet->tcp_header && !packet->udp_header) ||    // No TCP/UDP Header
        ( packet->flags & FLAG_STREAM_INSERT ))             // Waiting on stream reassembly
    {
        return;
    }

    PREPROC_PROFILE_START(sdfPerfStats);

    /* Retrieve the corresponding config for this packet */
    policy_id = _dpd.getRuntimePolicy();
    sfPolicyUserPolicySet (sdf_context_id, policy_id);
    config = sfPolicyUserDataGetCurrent(sdf_context_id);

    /* Retrieve stream session data. Create one if it doesn't exist. */
    session = _dpd.streamAPI->get_application_data(packet->stream_session_ptr, PP_SDF);
    if (session == NULL)
    {
        /* Do port checks */
        if (SDFCheckPorts(config, packet) == 0)
        {
            PREPROC_PROFILE_END(sdfPerfStats);
            return;
        }

        /* If there's no stream session, we'll just count PII for one packet */
        if (packet->stream_session_ptr == NULL)
        {
            if (config->stateless_session == NULL)
                config->stateless_session = NewSDFSession(config, packet);

            session = config->stateless_session;
            memset(session->counters, 0, session->num_patterns);
            memset(session->rtns_matched, 0, session->num_patterns);
        }
        else
            session = NewSDFSession(config, packet);
    }

    /* If HTTP Inspect left decoded buffers for us, we'll search those. */
    if (packet->num_uris > 0)
    {
        if (_dpd.uriBuffers[HTTP_BUFFER_URI]->uriLength > 0)
        {
            if (packet->num_uris > 0)
                exit(0);
            begin = (char *) _dpd.uriBuffers[HTTP_BUFFER_URI]->uriBuffer;
            buflen = _dpd.uriBuffers[HTTP_BUFFER_URI]->uriLength;
            end = begin + buflen;

            SDFSearch(config, packet, session, begin, end, buflen);
        }
        if (_dpd.uriBuffers[HTTP_BUFFER_CLIENT_BODY]->uriLength > 0)
        {
            begin = (char *) _dpd.uriBuffers[HTTP_BUFFER_CLIENT_BODY]->uriBuffer;
            buflen = _dpd.uriBuffers[HTTP_BUFFER_CLIENT_BODY]->uriLength;
            end = begin + buflen;

            SDFSearch(config, packet, session, begin, end, buflen);
        }
    }

    begin = (char *)packet->payload;
    buflen = packet->payload_size;
    end = begin + buflen;

    SDFSearch(config, packet, session, begin, end, buflen);

    /* End. */
    PREPROC_PROFILE_END(sdfPerfStats);
    return;
}


/*
 * Function: ParseSDFArgs(SDFConfig *, char *)
 *
 * Purpose: Parse the arguments to the SDF preprocessor and instantiate a
 *          SDFConfig struct.
 *
 * Arguments: config => pointer to a newly-allocated SDFConfig struct, which
 *                      will be modified.
 *            args => pointer to string containing SDF preproc arguments.
 *
 * Returns: void
 *
 */
static void ParseSDFArgs(SDFConfig *config, char *args)
{
    char *argcpy = NULL;
    char *cur_tokenp = NULL;

    if (config == NULL || args == NULL) return;

    /* Set default options */
    SSNSetDefaultGroups(config);

    /* Copy args so that we can break them up wtih strtok */
    argcpy = strdup(args);
    if (argcpy == NULL)
        DynamicPreprocessorFatalMessage("Could not allocate memory to parse " 
                                        "SDF options.\n");

    cur_tokenp = strtok(argcpy, " ");

    /* Loop through config options */
    while (cur_tokenp)
    {
        /* Parse the global PII threshold */
        if (!strcmp(cur_tokenp, SDF_THRESHOLD_KEYWORD))
        {
            char *endptr;
            
            cur_tokenp = strtok(NULL, " ");
            if (cur_tokenp == NULL)
            {
                DynamicPreprocessorFatalMessage("SDF preprocessor config option "
                        "\"%s\" requires an argument.\n", SDF_THRESHOLD_KEYWORD);
            }

            if (*cur_tokenp == '-')
            {
                DynamicPreprocessorFatalMessage("SDF preprocessor config option "
                        "\"%s\" cannot take a negative argument.\n",
                        SDF_THRESHOLD_KEYWORD);
            }

            config->threshold = _dpd.SnortStrtoul(cur_tokenp, &endptr, 10);
            if (config->threshold == 0 || errno == ERANGE)
            {
                DynamicPreprocessorFatalMessage("SDF preprocessor config option "
                        "\"%s\" must have an argument between 1 - %u.\n",
                        SDF_THRESHOLD_KEYWORD, ULONG_MAX);
            }
            if (*endptr != '\0')
            {
                DynamicPreprocessorFatalMessage("Invalid argument to SDF config "
                        "option \"%s\": %s", SDF_THRESHOLD_KEYWORD, cur_tokenp);
            }
        }
        /* Parse the output masking option */
        else if (!strcmp(cur_tokenp, SDF_MASK_KEYWORD))
        {
            config->mask_output = 1;
        }
        /* Parse the file containing new SSN group data */
        else if (!strcmp(cur_tokenp, SDF_SSN_FILE_KEYWORD))
        {
            int iRet;

            cur_tokenp = strtok(NULL, " ");
            if (cur_tokenp == NULL)
            {
                DynamicPreprocessorFatalMessage("SDF preprocessor config option "
                        "\"%s\" requires an argument.\n", SDF_SSN_FILE_KEYWORD);
            }

            iRet = ParseSSNGroups(cur_tokenp, config);
            if (iRet < 0)
            {
                DynamicPreprocessorFatalMessage("Error parsing Social Security "
                        "group data from file: %s", cur_tokenp);
            }
        }

        cur_tokenp = strtok(NULL, " ");
    }

    /* Cleanup */
    free(argcpy);
    argcpy = NULL;
}

/* Allocate & Initialize the pseudo-packet used for logging combo alerts.
 *
 * Returns: 0 on success, -1 on error.
 */
static int SDFPacketInit(SDFConfig *config)
{
    const char mac_addr[] = "MACDAD";
    SFSnortPacket *p;

    if (config == NULL)
        return -1;

    p = (SFSnortPacket *) calloc(1, sizeof(SFSnortPacket));
    if (p == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory for SDF "
                    "pseudo-packet.");
    }

    p->pcap_header = (struct pcap_pkthdr *) calloc(1, sizeof(struct pcap_pkthdr) +
                    ETHER_HDR_LEN + VLAN_HDR_LEN + SUN_SPARC_TWIDDLE + IP_MAXPKT);

    /* This is a space holder in case we get a packet with a vlan header.  It
     * is not used in the packet created, but in unified2 logging */
    p->vlan_tag_header   = (void *)((u_char *)p->pcap_header + sizeof(struct pcap_pkthdr));

    /* Add 2 to align iph struct members on 4 byte boundaries - for sparc, etc */
    p->pkt_data  = (u_char *)p->vlan_tag_header + VLAN_HDR_LEN + SUN_SPARC_TWIDDLE;
    p->ether_header   = (EtherHeader *)((u_char *)p->pkt_data);
    p->ip4_header  = (IPV4Header *)((u_char *)p->ether_header + ETHER_HDR_LEN);
    p->payload = (u_char *)p->ip4_header + sizeof(IPV4Header);

    /*
    **  Set the ethernet header with our cooked values.
    */
    ((EtherHeader *)p->ether_header)->ethernet_type = htons(0x0800);
    memcpy(((EtherHeader *)p->ether_header)->ether_destination, mac_addr, 6);
    memcpy(((EtherHeader *)p->ether_header)->ether_source, mac_addr, 6);

    config->pseudo_packet = p;

    return 0;
}

/*
 * Function: NewSDFConfig(void)
 *
 * Purpose: Create a new SDFConfig for the current parser policy.
 *
 * Arguments: context => context ID to use when creating config
 *
 * Returns: Pointer to newly created SDFConfig struct.
 *
 */
static SDFConfig * NewSDFConfig(tSfPolicyUserContextId context)
{
    SDFConfig *config = NULL;
    tSfPolicyId policy_id = _dpd.getParserPolicy();
   
    /* Check for an existing configuration in this policy */
    sfPolicyUserPolicySet(context, policy_id);

    config = (SDFConfig *) sfPolicyUserDataGetCurrent(context);
    if (config)
        DynamicPreprocessorFatalMessage("SDF preprocessor can only be "
                                        "configured once.\n");

    /* Create and store config */
    config = (SDFConfig *)calloc(1, sizeof(SDFConfig));
    if (!config)
        DynamicPreprocessorFatalMessage("Failed to allocate memory for SDF "
                                        "configuration.\n");
    sfPolicyUserDataSetCurrent(context, config);

    /* Allocate the pseudo-packet used for logging */
    SDFPacketInit(config);

    return config;
}

/*
 * Function: SDFCleanExit(int, void *)
 *
 * Purpose: Free memory used by the SDF preprocessor before Snort exits.
 *
 * Arguments: Signal sent to Snort, unused void pointer
 *
 * Returns: void
 *
 */
static void SDFCleanExit(int signal, void *unused)
{
    /* Free the individual configs. */
    if (sdf_context_id == NULL)
        return;

    sfPolicyUserDataIterate(sdf_context_id, SDFFreeConfig);
    sfPolicyConfigDelete(sdf_context_id);
    sdf_context_id = NULL;

    if (head_node)
        FreePiiTree(head_node);
}

/*
 * Function: SDFFreeConfig(tSfPolicyUserContextId, tSfPolicyId, void *)
 *
 * Purpose: Callback that frees a SDFConfig struct correctly, and clears data
 *          from the policy.
 *
 * Arguments: context => context ID for the SDF preprocessor
 *            id => policy ID for the policy being destroyed
 *            pData => pointer to SDFConfig struct that gets freed
 *
 * Returns: zero
 *
 */
static int SDFFreeConfig(tSfPolicyUserContextId context, tSfPolicyId id, void *pData)
{
    SDFConfig *config = (SDFConfig *)pData;

    sfPolicyUserDataClear(context, id);
        
    free((void *)config->pseudo_packet->pcap_header);
    free(config->pseudo_packet);
    FreeSDFSession(config->stateless_session);

    free(config);
    return 0;
}

#ifdef SNORT_RELOAD
static void SDFReload(char *args)
{
    SDFConfig *config = NULL;

    if (sdf_swap_context_id == NULL)
    {
        sdf_swap_context_id = sfPolicyConfigCreate();

        if (sdf_swap_context_id == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate "
                                            "memory for SDF config.\n");
        }

        if (_dpd.streamAPI == NULL)
        {
            DynamicPreprocessorFatalMessage("SetupSDF(): The Stream preprocessor "
                                            "must be enabled.\n");
        }

        /* Allocate the head of the pattern-matching tree */
        swap_head_node = (sdf_tree_node *)calloc(1, sizeof(sdf_tree_node));
        if (!swap_head_node)
        DynamicPreprocessorFatalMessage("Failed to allocate memory for SDF "
                                        "configuration.\n"); 
    }

    config = NewSDFConfig(sdf_swap_context_id);
    ParseSDFArgs(config, args);

    _dpd.addPreproc(ProcessSDF, PRIORITY_LAST, PP_SDF,
            PROTO_BIT__TCP | PROTO_BIT__UDP);
    _dpd.preprocOptRegister(SDF_OPTION_NAME, SDFOptionInit, SDFOptionEval,
                                NULL, NULL, NULL, SDFOtnHandler, NULL);
}

static void * SDFReloadSwap(void)
{
    tSfPolicyUserContextId old_context_id = sdf_context_id;
    sdf_tree_node *old_head_node = head_node;

    if (old_context_id == NULL || sdf_swap_context_id == NULL ||
        old_head_node == NULL || swap_head_node == NULL)
        return NULL;

    sdf_context_id = sdf_swap_context_id;
    sdf_swap_context_id = NULL;

    head_node = swap_head_node;
    num_patterns = swap_num_patterns;

    FreePiiTree(old_head_node);
    swap_head_node = NULL;
    swap_num_patterns = 0;

    return (void *) old_context_id;
}

static void SDFReloadSwapFree(void *data)
{
    tSfPolicyUserContextId context = (tSfPolicyUserContextId) data;
    if (context == NULL)
        return;

    sfPolicyUserDataIterate(context, SDFFreeConfig);
    sfPolicyConfigDelete(context);
}
#endif

/*
*  checksum IP  - header=20+ bytes
*
*  w - short words of data
*  blen - byte length
* 
*/
static INLINE unsigned short in_chksum_ip(  unsigned short * w, int blen )
{
   unsigned int cksum;

   /* IP must be >= 20 bytes */
   cksum  = w[0];
   cksum += w[1];
   cksum += w[2];
   cksum += w[3];
   cksum += w[4];
   cksum += w[5];
   cksum += w[6];
   cksum += w[7];
   cksum += w[8];
   cksum += w[9];

   blen  -= 20;
   w     += 10;

   while( blen ) /* IP-hdr must be an integral number of 4 byte words */
   {
     cksum += w[0];
     cksum += w[1];
     w     += 2;
     blen  -= 4;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short) (~cksum);
}

static void SDFPrintPseudoPacket(SDFConfig *config, SDFSessionData *session,
                                 SFSnortPacket *real_packet)
{
    SFSnortPacket *p;
    uint16_t hlen = 0;
    uint16_t dlen = 0;

    if (config == NULL || session == NULL || real_packet == NULL)
        return;

    p = config->pseudo_packet;

    /* First, copy over the VLAN & IP headers of the offending packet */
    if (real_packet->vlan_tag_header != NULL)
        memcpy((void *)p->vlan_tag_header, real_packet->vlan_tag_header, VLAN_HDR_LEN);

    if (real_packet->ether_header != NULL)
        ((EtherHeader *)p->ether_header)->ethernet_type = real_packet->ether_header->ethernet_type;

    /* IPv4 */
    if (real_packet->family == AF_INET)
    {
        /* Header length is given as 4 bits counter of 32-bit words. */
        hlen = ((real_packet->ip4_header->version_headerlength) & 0x0F) << 2;
        memcpy((void *)p->ip4_header, real_packet->ip4_header, hlen);
        ((IPV4Header *)p->ip4_header)->time_to_live = 0;
        ((IPV4Header *)p->ip4_header)->proto = 0xFE;
        p->payload = (u_int8_t *)p->ip4_header + hlen;
#ifdef SUP_IP6
        _dpd.ip6Build(p, p->ip4_header, real_packet->family);
#endif
    }
    /* IPv6 */
#ifdef SUP_IP6
    else
    {
        _dpd.ip6Build(p, real_packet->ip4_header, real_packet->family);
        hlen = sizeof(IP6Hdr);
        p->inner_ip6h.hop_lmt = 0;
        p->inner_ip6h.next = 0xFE;
        p->payload = (u_int8_t *)p->ip4_header + hlen;
    }
#endif

    /* Fill in the payload with SDF alert info */
    dlen = hlen;
    SDFFillPacket(head_node, session, p, &dlen);

    p->payload_size = dlen - hlen;

    /* Fix the checksum. Only applies to IPv4. */
    if (p->family == AF_INET)
    {
        unsigned short checksum;
        ((IPV4Header *)p->ip4_header)->checksum = 0;
        checksum = in_chksum_ip((unsigned short *)p->ip4_header,
                                (int) hlen);

        ((IPV4Header *)p->ip4_header)->checksum = checksum;
    }
#ifdef SUP_IP6
    else
    {
        /* Fix the payload length. Only applies to IPv6. */
        p->ip6h->len = htons(p->payload_size);
    }
#endif

    /* Fill in pcap header */
    ((struct pcap_pkthdr *)p->pcap_header)->ts.tv_sec = real_packet->pcap_header->ts.tv_sec;
    ((struct pcap_pkthdr *)p->pcap_header)->ts.tv_usec = real_packet->pcap_header->ts.tv_usec;
    ((struct pcap_pkthdr *)p->pcap_header)->caplen = dlen + ETHER_HDR_LEN;
    ((struct pcap_pkthdr *)p->pcap_header)->len = p->pcap_header->caplen;
}

/* This function traverses the pattern tree and prints out the relevant
 * info into a provided pseudo-packet. */
static void SDFFillPacket(sdf_tree_node *node, SDFSessionData *session,
                          SFSnortPacket *p, uint16_t *dlen)
{
    uint16_t i, space_left;

    if (node == NULL || session == NULL || p == NULL || dlen == NULL)
        return;

    /* Recurse to the leaves of the pattern tree */
    for (i = 0; i < node->num_children; i++)
    {
        SDFFillPacket(node->children[i], session, p, dlen);
    }

    /* Print the info from leaves */
    if (node->option_data)
    {
        uint32_t index = node->option_data->counter_index;
        uint8_t counter = session->counters[index];
        if (counter > 0)
        {
            /* Print line */
            char *sigmessage = node->option_data->otn->sigInfo.message;
            u_int8_t *dest = (u_int8_t *)p->ip4_header + *dlen;
            size_t siglen = strlen(sigmessage);

            space_left = IP_MAXPKT - *dlen;

            if (space_left < siglen + SDF_ALERT_LENGTH)
                return;

            *dlen += (siglen + SDF_ALERT_LENGTH); 
            snprintf((char *)dest, space_left, "%s: %3d", sigmessage, counter);
        }
    }

    return;
}


