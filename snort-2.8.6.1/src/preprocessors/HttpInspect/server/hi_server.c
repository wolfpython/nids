/****************************************************************************
 *
 * Copyright (C) 2003-2010 Sourcefire, Inc.
 *
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
 ****************************************************************************/
 
/**
**  @file       hi_server.c
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Handles inspection of HTTP server responses.
**  
**  HttpInspect handles server responses in a stateless manner because we
**  are really only interested in the first response packet that contains
**  the HTTP response code, headers, and the payload.
**  
**  The first big thing is to incorporate the HTTP protocol flow
**  analyzer.
**  
**  NOTES:
**      - Initial development.  DJR
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#ifdef ZLIB
#include <zlib.h>
#include "mempool.h"
extern MemPool *hi_gzip_mempool;
#endif

#include "hi_server.h"
#include "hi_ui_config.h"
#include "hi_return_codes.h"
#include "hi_si.h"
#include "bounds.h"

#define STAT_END 100
#define HTTPRESP_HEADER_NAME__COOKIE "Set-Cookie"
#define HTTPRESP_HEADER_LENGTH__COOKIE 10
#define HTTPRESP_HEADER_NAME__CONTENT_ENCODING "Content-Encoding"
#define HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING 16
#define HTTPRESP_HEADER_NAME__GZIP "gzip"
#define HTTPRESP_HEADER_LENGTH__GZIP 4
#define HTTPRESP_HEADER_NAME__DEFLATE "deflate"
#define HTTPRESP_HEADER_LENGTH__DEFLATE 7
#define HTTPRESP_HEADER_NAME__CONTENT_LENGTH "Content-length"
#define HTTPRESP_HEADER_LENGTH__CONTENT_LENGTH 14


typedef int (*LOOKUP_FCN)(HI_SESSION *, const u_char *, const u_char *, const u_char **,
                URI_PTR *);
extern LOOKUP_FCN lookup_table[256];
extern int hex_lookup[256];
extern uint8_t DecodeBuffer[DECODE_BLEN];
extern int NextNonWhiteSpace(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int CheckChunkEncoding(HI_SESSION *, const u_char *, const u_char *, const u_char **, u_char *, int , int, int *);
extern int IsHttpVersion(const u_char **, const u_char *);
extern int find_rfc_delimiter(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int find_non_rfc_delimiter(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int NextNonWhiteSpace(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetPercentNorm(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetSlashNorm(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetBackSlashNorm(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetPlusNorm(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetBinaryNorm(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetParamField(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern int SetProxy(HI_SESSION *, const u_char *, const u_char *, const u_char **, URI_PTR *);
extern const u_char *extract_http_cookie(const u_char *p, const u_char *end, HEADER_PTR *, HEADER_FIELD_PTR *);



#define CLR_SERVER_HEADER(Server) \
    do { \
            Server->response.header_raw = NULL;\
            Server->response.header_raw_size = 0;\
            Server->response.header_norm = NULL; \
            Server->response.header_norm_size = 0 ;\
            Server->response.cookie.cookie = NULL;\
            Server->response.cookie.cookie_end = NULL;\
            Server->response.cookie.next = NULL;\
            Server->response.cookie_norm = NULL;\
            Server->response.cookie_norm_size = 0;\
    } while(0);

#define CLR_SERVER_STAT(Server) \
    do { \
            Server->response.status_msg = NULL;\
            Server->response.status_code = NULL;\
            Server->response.status_code_size = 0;\
            Server->response.status_msg_size = 0;\
    }while(0);

#define CLR_SERVER_BODY(Server)\
    do { \
            Server->response.body = NULL;\
            Server->response.body_size = 0;\
    }while(0);

static INLINE void clearHttpRespBuffer(HI_SERVER *Server)
{
    CLR_SERVER_HEADER(Server);
    CLR_SERVER_STAT(Server);
    CLR_SERVER_BODY(Server);
}


/**
**  NAME
**    IsHttpServerData::
*/
/**
**  Inspect an HTTP server response packet to determine the state.
**  
**  We inspect this packet and determine whether we are in the beginning
**  of a response header or if we are looking at payload.  We limit the
**  amount of inspection done on responses by only inspecting the HTTP header
**  and some payload.  If the whole packet is a payload, then we just ignore
**  it, since we inspected the previous header and payload.
**  
**  We limit the amount of the payload by adjusting the Server structure
**  members, header and header size.
**  
**  @param Server      the server structure
**  @param data        pointer to the beginning of payload
**  @param dsize       the size of the payload
**  @param flow_depth  the amount of header and payload to inspect
**  
**  @return integer
**  
**  @retval HI_INVALID_ARG invalid argument
**  @retval HI_SUCCESS     function success
*/
static int IsHttpServerData(HI_SERVER *Server, const u_char *data, int dsize,
                            int flow_depth)
{
    clearHttpRespBuffer(Server);
    /* 
    ** HTTP:Server-Side-Session-Performance-Optimization
    ** This drops Server->Client packets which are not part of the 
    ** HTTP Response header. It can miss part of the response header 
    ** if the header is sent as multiple packets.
    */
    if(!data)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Let's set up the data pointers.
    */
    Server->response.header_raw      = data;
    Server->response.header_raw_size = dsize;

    /*
    **  This indicates that we want to inspect the complete response, so
    **  we don't waste any time otherwise.
    */
    if(flow_depth < 1)
    {
        return HI_SUCCESS;
    }

    if(dsize > 4 )
    {
        if( (data[0]!='H') || (data[1]!='T') || 
            (data[2]!='T') || (data[3]!='P') )
        {
            Server->response.header_raw_size = 0;
            Server->response.header_raw      = NULL;
            Server->response.header_norm     = NULL;

            return HI_SUCCESS;
        }

        /*
        **  OK its an HTTP response header.
        **
        **  Now, limit the amount we inspect,
        **  we could just examine this whole packet, 
        **  since it's usually full of HTTP Response info.
        **  For protocol analysis purposes we probably ought to 
        **  let the whole thing get processed, or have a 
        **  different pattern match length and protocol inspection 
        **  length.
        */

        if(dsize > flow_depth)
        {
            Server->response.header_raw_size = flow_depth;  
        }
    }

    return HI_SUCCESS;
}

static INLINE int hi_server_extract_status_msg( const u_char *start, const u_char *ptr, 
        const u_char *end, URI_PTR *result)
{
    int iRet = HI_SUCCESS;
    SkipBlankSpace(start,end,&ptr);

    if (  hi_util_in_bounds(start, end, ptr) )
    {
        const u_char *crlf = (u_char *)SnortStrnStr((const char *)ptr, end - ptr, "\n");
        result->uri = ptr;
        if (crlf)
        {
            result->uri_end = crlf + 1;
            ptr = crlf;
        }
        else
        {
            result->uri_end =end;
        }
        iRet = STAT_END;
    }
    else
        iRet = HI_OUT_OF_BOUNDS;

    return iRet;
}


static INLINE int hi_server_extract_status_code( const u_char *start, const u_char *ptr, 
        const u_char *end, URI_PTR *result)
{
    int iRet = HI_SUCCESS;
    SkipBlankSpace(start,end,&ptr);

    if (  hi_util_in_bounds(start, end, ptr) )
    {
        if(isdigit((int)*ptr))
        {
            result->uri = ptr;
            SkipDigits(start, end, &ptr);
            if (  hi_util_in_bounds(start, end, ptr) )
            {
                if(isspace((int)*ptr))
                {
                    result->uri_end = ptr;
                    iRet = STAT_END;
                }
                else
                {
                    iRet = HI_NONFATAL_ERR;
                }

            }
            else
                iRet = HI_OUT_OF_BOUNDS;

        }
        else
            iRet = HI_NONFATAL_ERR;
    }
    else
        iRet = HI_OUT_OF_BOUNDS;

    return iRet;
}

#ifdef ZLIB
static INLINE const u_char *extract_http_content_encoding(HTTPINSPECT_CONF *ServerConf, 
        const u_char *p, const u_char *start, const u_char *end, HEADER_PTR *header_ptr, 
        HEADER_FIELD_PTR *header_field_ptr)
{
    const u_char *crlf;
    int space_present = 0;
    if (header_ptr->content_encoding.cont_encoding_start)
    {
        header_ptr->header.uri_end = p;
        header_ptr->content_encoding.compress_fmt = 0;
        return p;
    }
    else
    {
        header_field_ptr->content_encoding = &header_ptr->content_encoding;
        p = p + HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING;
    }
    SkipBlankSpace(start,end,&p);
    if(hi_util_in_bounds(start, end, p) && *p == ':')
    {
        p++;
        if (  hi_util_in_bounds(start, end, p) )
        {
            if ( ServerConf->profile == HI_APACHE || ServerConf->profile == HI_ALL)
            {
                SkipWhiteSpace(start,end,&p);
            }
            else
            {
                SkipBlankAndNewLine(start,end,&p);
            }
            if( hi_util_in_bounds(start, end, p))
            {
                if ( *p == '\n' )
                {
                    while(hi_util_in_bounds(start, end, p))
                    {
                        if ( *p == '\n')
                        {
                            p++;
                            while( hi_util_in_bounds(start, end, p) && ( *p == ' ' || *p == '\t'))
                            {
                                space_present = 1;
                                p++;
                            }
                            if ( space_present )
                            {
                                if ( isalpha((int)*p))
                                    break;
                                else if(isspace((int)*p) && (ServerConf->profile == HI_APACHE || ServerConf->profile == HI_ALL) )
                                {
                                    SkipWhiteSpace(start,end,&p);
                                }
                                else
                                {
                                    header_field_ptr->content_encoding->cont_encoding_start=
                                        header_field_ptr->content_encoding->cont_encoding_end = NULL;
                                    header_field_ptr->content_encoding->compress_fmt = 0;
                                    return p;
                                }
                            }
                            else
                            {
                                header_field_ptr->content_encoding->cont_encoding_start=
                                    header_field_ptr->content_encoding->cont_encoding_end = NULL;
                                header_field_ptr->content_encoding->compress_fmt = 0;
                                return p;
                            }
                        }
                        else
                            break;
                    }
                }
                else if(isalpha((int)*p))
                {
                    header_field_ptr->content_encoding->cont_encoding_start = p;
                    while(hi_util_in_bounds(start, end, p) && *p!='\n' )
                    {
                        if(IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__GZIP, HTTPRESP_HEADER_LENGTH__GZIP))
                        {
                            header_field_ptr->content_encoding->compress_fmt |= HTTP_RESP_COMPRESS_TYPE__GZIP;
                            p = p + HTTPRESP_HEADER_LENGTH__GZIP;
                            continue;
                        }
                        else if(IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__DEFLATE, HTTPRESP_HEADER_LENGTH__DEFLATE))
                        {
                            header_field_ptr->content_encoding->compress_fmt |= HTTP_RESP_COMPRESS_TYPE__DEFLATE;
                            p = p + HTTPRESP_HEADER_LENGTH__DEFLATE;
                            continue;
                        }
                        else
                            p++;
                    }

                    /*crlf = (u_char *)SnortStrnStr((const char *)p, end - p, "\n");
                    if(crlf)
                    {
                        p = crlf;
                    }
                    else
                    {
                        header_ptr->header.uri_end = end ;
                        return end;
                    }*/
                }
                else
                {
                    header_field_ptr->content_encoding->cont_encoding_start=
                        header_field_ptr->content_encoding->cont_encoding_end = NULL;
                    header_field_ptr->content_encoding->compress_fmt = 0;
                    return p;
                }
            }
        }
    }
    else
    {
        if(hi_util_in_bounds(start, end, p))
        {
            crlf = (u_char *)SnortStrnStr((const char *)p, end - p, "\n");
            if(crlf)
            {
                p = crlf;
            }
            else
            {
                header_ptr->header.uri_end = end ;
                return end;
            }
        }
    }
    if(!p || !hi_util_in_bounds(start, end, p))
        p = end;

    return p;
}
#endif


static INLINE const u_char *extractHttpRespHeaderFieldValues(HTTPINSPECT_CONF *ServerConf, 
        const u_char *p, const u_char *offset, const u_char *start, 
        const u_char *end, HEADER_PTR *header_ptr, 
        HEADER_FIELD_PTR *header_field_ptr, int parse_cont_encoding)
{
    if (((p - offset) == 0) && ((*p == 'S') || (*p == 's')))
    {
        /* Search for 'Cookie' at beginning, starting from current *p */
        if ( ServerConf->enable_cookie && 
                IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__COOKIE, 
                    HTTPRESP_HEADER_LENGTH__COOKIE))
        {
            p = extract_http_cookie(p, end, header_ptr, header_field_ptr);
        }
    }
    else if (((p - offset) == 0) && ((*p == 'C') || (*p == 'c')))
    {
#ifdef ZLIB
        if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__CONTENT_ENCODING, 
                    HTTPRESP_HEADER_LENGTH__CONTENT_ENCODING) && ServerConf->extract_gzip &&
                    parse_cont_encoding) 
        {
            p = extract_http_content_encoding(ServerConf, p, start, end, header_ptr, header_field_ptr );
        }
        else 
#endif
        {
            if ( IsHeaderFieldName(p, end, HTTPRESP_HEADER_NAME__CONTENT_LENGTH, 
                    HTTPRESP_HEADER_LENGTH__CONTENT_LENGTH) )
            {
                if(header_ptr)
                {
                    header_ptr->content_len.len = 1;
                }
            }
        }
    }
    return p;
}


static INLINE const u_char *hi_server_extract_header(
        HI_SESSION *Session, HTTPINSPECT_CONF *ServerConf, 
            HEADER_PTR *header_ptr, const u_char *start, 
            const u_char *end, int parse_cont_encoding)
{
    const u_char *p;
    const u_char *offset;
    HEADER_FIELD_PTR header_field_ptr ;

    if(!start || !end)
        return NULL;

    p = start;

    offset = (u_char*)p;

    header_ptr->header.uri = p;
    header_ptr->content_encoding.compress_fmt = 0;
    header_ptr->content_len.len = 0;

    while (hi_util_in_bounds(start, end, p))
    {
        if(*p == '\n')
        {
            p++;

            offset = (u_char*)p;

            if (!hi_util_in_bounds(start, end, p))
            {
                header_ptr->header.uri_end = p;
                return p;
            }

            if (*p < 0x0E)
            {
                if(*p == '\r')
                {
                    p++;

                    if(hi_util_in_bounds(start, end, p) && (*p == '\n'))
                    {
                        header_ptr->header.uri_end = p;
                        return ++p;
                    }
                }
                else if(*p == '\n')
                {
                    header_ptr->header.uri_end = p;
                    return ++p;
                }
            }
            else if ( (p = extractHttpRespHeaderFieldValues(ServerConf, p, offset, 
                            start, end, header_ptr, &header_field_ptr, 
                            parse_cont_encoding)) == end)
            {
                return end;
            }

        }
        else if( (p == header_ptr->header.uri) && 
                (p = extractHttpRespHeaderFieldValues(ServerConf, p, offset, 
                          start, end, header_ptr, &header_field_ptr,
                          parse_cont_encoding)) == end)
        {
            return end;
        }
        if ( *p == '\n') continue;
        p++;
    }

    header_ptr->header.uri_end = p;
    return p;
}

static INLINE int hi_server_extract_body(
                    HI_SESSION *Session, HTTPINSPECT_CONF *ServerConf,
                    const u_char *ptr, const u_char *end, URI_PTR *result, 
                    int content_length)
{
    const u_char *start = ptr;
    int iRet = HI_SUCCESS;
    const u_char *post_end = end; 
    if( ServerConf->server_flow_depth && ((end - ptr) > ServerConf->server_flow_depth) )
    {
        end = ptr + ServerConf->server_flow_depth;
    }

    if ((!content_length))
    {
        if ( ServerConf->chunk_length && (CheckChunkEncoding(Session, start, end, &post_end, NULL, 
                        0, 0, NULL) == 1) )
        {
            result->uri = start;
            result->uri_end = post_end;
            return iRet;
        }
        else
        {
            return HI_NONFATAL_ERR;
        }

    }

    result->uri = start;
    result->uri_end = end;

    return STAT_END;
}

#ifdef ZLIB
static void SetGzipBuffers(HttpSessionData *hsd, HI_SESSION *session)
{
    if ((hsd != NULL) && (hsd->decomp_state == NULL)
            && (session != NULL) && (session->server_conf != NULL)
            && (session->global_conf != NULL) && session->server_conf->extract_gzip)
    {
        MemBucket *bkt = mempool_alloc(hi_gzip_mempool);

        if (bkt != NULL)
        {
            hsd->decomp_state = (DECOMPRESS_STATE *)SnortAlloc(sizeof(DECOMPRESS_STATE));
            hsd->decomp_state->gzip_bucket = bkt;
            hsd->decomp_state->compr_depth = session->global_conf->compr_depth;
            hsd->decomp_state->decompr_depth = session->global_conf->decompr_depth;
            hsd->decomp_state->compr_buffer = (unsigned char *)bkt->data;
            hsd->decomp_state->decompr_buffer = (unsigned char *)bkt->data + session->global_conf->compr_depth;
        }
    }
}

int uncompress_gzip ( u_char *dest, int destLen, u_char *source, 
        int sourceLen, HttpSessionData *sd, int *total_bytes_read, int first_pkt)
{
    z_stream stream;
    int err;

   stream = sd->decomp_state->d_stream;

   stream.next_in = (Bytef*)source;
   stream.avail_in = (uInt)sourceLen;
   if ((uLong)stream.avail_in != (uLong)sourceLen)
   {
       sd->decomp_state->d_stream = stream;
       return HI_NONFATAL_ERR;
   }

   stream.next_out = dest;
   stream.avail_out = (uInt)destLen;
   if ((uLong)stream.avail_out != (uLong)destLen)
   { 
       sd->decomp_state->d_stream = stream;
       return HI_NONFATAL_ERR;
   }

   if(first_pkt)
   {
       stream.zalloc = (alloc_func)0;
       stream.zfree = (free_func)0;
       err = inflateInit2(&stream, 31);
       if (err != Z_OK)
       {
           sd->decomp_state->d_stream = stream;
           return HI_NONFATAL_ERR;
       }
   }
   else
   {
       stream.total_in = 0;
       stream.total_out =0;
   }


   err = inflate(&stream, Z_STREAM_END);
   if ((err != Z_STREAM_END) && (err !=Z_OK)) {
       inflateEnd(&stream);
       sd->decomp_state->d_stream = stream;
       return HI_NONFATAL_ERR;
   }
   *total_bytes_read = stream.total_out;
   sd->decomp_state->d_stream = stream;
   return HI_SUCCESS;
}

static INLINE int hi_server_decompress(HI_SESSION *Session, HttpSessionData *sd, const u_char *ptr, 
        const u_char *end, URI_PTR *result, int contlen, int first_pkt)
{
    const u_char *start = ptr;
    int rawbuf_size = end - ptr;
    int iRet = HI_SUCCESS;
    int zRet = HI_NONFATAL_ERR;
    int compr_depth, decompr_depth;
    int compr_bytes_read, decompr_bytes_read;
    int compr_avail, decompr_avail;
    int total_bytes_read = 0;
    int chunk_size = 0;
    
    u_char *compr_buffer;
    u_char *decompr_buffer;
    if(!Session || !sd || !sd->decomp_state)
    {
        if ((sd != NULL) && (sd->decomp_state != NULL))
            ResetGzipState(sd->decomp_state);
        return HI_INVALID_ARG;
    }
    compr_depth = sd->decomp_state->compr_depth;
    decompr_depth = sd->decomp_state->decompr_depth;
    compr_bytes_read = sd->decomp_state->compr_bytes_read;
    decompr_bytes_read = sd->decomp_state->decompr_bytes_read;
    compr_avail = compr_depth-compr_bytes_read;
    decompr_avail = decompr_depth - decompr_bytes_read;
    compr_buffer = sd->decomp_state->compr_buffer;
    decompr_buffer = sd->decomp_state->decompr_buffer;

    if(compr_avail <=0 || decompr_avail <=0 ||
            (!compr_buffer) || (!decompr_buffer))
    {
        ResetGzipState(sd->decomp_state);
        return iRet;
    }

    if(sd->decomp_state->last_pkt_chunked)
        contlen = 0;

    if(rawbuf_size < compr_avail)
    {
        compr_avail = rawbuf_size;
    }

    if(!contlen)
    {
        if(CheckChunkEncoding(Session, start, end, NULL, compr_buffer, compr_avail,
                    sd->decomp_state->last_chunk_size, &chunk_size ) == 1)
        {
            sd->decomp_state->last_pkt_chunked = 1;
            sd->decomp_state->last_chunk_size = chunk_size;
            zRet = uncompress_gzip(decompr_buffer,decompr_avail,compr_buffer, compr_avail, sd, &total_bytes_read,
                    first_pkt);
        }
    }
    else
    {
        memcpy(compr_buffer, ptr, compr_avail);
        zRet = uncompress_gzip(decompr_buffer,decompr_avail,compr_buffer, compr_avail, sd, &total_bytes_read,
                first_pkt);
    }
    
    sd->decomp_state->compr_bytes_read += compr_avail;
    hi_stats.compr_bytes_read += compr_avail;

    if(!zRet)
    {
        if(decompr_buffer)
        {
            result->uri = decompr_buffer;
            if ( total_bytes_read < decompr_avail )
            {
                result->uri_end = decompr_buffer + total_bytes_read;
                sd->decomp_state->decompr_bytes_read += total_bytes_read;
                hi_stats.decompr_bytes_read += total_bytes_read;
            }
            else
            {
                result->uri_end = decompr_buffer + decompr_avail;
                sd->decomp_state->decompr_bytes_read += decompr_avail;
                hi_stats.decompr_bytes_read += decompr_avail;
            }
        }
    }
    else
    {
        ResetGzipState(sd->decomp_state);
    }

    return iRet;


}
#endif
            

int HttpResponseInspection(HI_SESSION *Session, Packet *p, const unsigned char *data,
        int dsize, HttpSessionData *sd)
{
    HTTPINSPECT_CONF *ServerConf;
    URI_PTR stat_code_ptr;
    URI_PTR stat_msg_ptr;
    HEADER_PTR header_ptr;
    URI_PTR body_ptr;
    HI_SERVER *Server;
    const u_char *start;
    const u_char *end;
    const u_char *ptr;
    int len;
    int parse_cont_encoding = 1;
    int iRet = 0;
#ifdef ZLIB
    int expected_pkt = 0;
    int status;
    int alt_dsize;
#endif

    if (!Session || !p || !data || (dsize == 0))
        return HI_INVALID_ARG;

    ServerConf = Session->server_conf;
    if(!ServerConf)
        return HI_INVALID_ARG;

#ifdef ZLIB
    if (ServerConf->extract_gzip && (sd != NULL) && (sd->decomp_state != NULL))
    {
        /* If the previously inspected packet in this session identified gzip
         * and if the packets are stream inserted wait for reassembled */
        if (sd->decomp_state->inspect_reassembled)
        {
            if(p->packet_flags & PKT_STREAM_INSERT)
                parse_cont_encoding = 0;
        }

        /* If this packet is the next expected packet to be decompressed and is out of sequence 
         * clear out the decompression state*/
        if( sd->decomp_state->decompress_data && 
                parse_cont_encoding)
        {
            if( sd->decomp_state->next_seq &&
                    (ntohl(p->tcph->th_seq) == sd->decomp_state->next_seq) )
            {
                sd->decomp_state->next_seq = ntohl(p->tcph->th_seq) + p->dsize;
                expected_pkt = 1;
            }
            else
            {
                ResetGzipState(sd->decomp_state);
            }
        }
    }
#endif

    Server = &(Session->server);

    memset(&stat_code_ptr, 0x00, sizeof(URI_PTR));
    memset(&stat_msg_ptr, 0x00, sizeof(URI_PTR));
    memset(&header_ptr, 0x00, sizeof(HEADER_PTR));
    memset(&body_ptr, 0x00, sizeof(URI_PTR));

    start = data;
    end = data + dsize;
    ptr = start;

    clearHttpRespBuffer(Server);
    /* moving past the CRLF */

    while(hi_util_in_bounds(start, end, ptr))
    {
        if(*ptr < 0x21)
        {
            if(*ptr < 0x0E && *ptr > 0x08)
            {
                ptr++;
                continue;
            }
            else
            {
                if(*ptr == 0x20)
                {
                    ptr++;
                    continue;
                }
            }
        }

        break;
    }

    /*after doing this we need to basically check for version, status code and status message*/

    len = end - ptr;
    if ( dsize > 4 )
    {
        if(!IsHttpVersion(&ptr, end))
        { 
#ifdef ZLIB
            if(expected_pkt)
            {
                ptr = start;
            }
            else
#endif
            {
#ifdef ZLIB
                if ((sd != NULL) && (sd->decomp_state != NULL))
                    ResetGzipState(sd->decomp_state);
#endif
                CLR_SERVER_HEADER(Server);
                if (ServerConf->server_flow_depth < 1 )
                {
                    Server->response.header_raw = data;
                    Server->response.header_raw_size = dsize;
                }
                return HI_SUCCESS;
            }
        }
        else
        {
#ifdef ZLIB
            /* This is a next expected packet to be decompressed but the packet is a
             * valid HTTP response. So the gzip decompression ends here */
            if(expected_pkt)
            {
                expected_pkt = 0;
                ResetGzipState(sd->decomp_state);
            }
#endif
            while(hi_util_in_bounds(start, end, ptr))
            {
                if (isspace((int)*ptr))
                    break;
                ptr++;
            }

        }
    }

#ifdef ZLIB
    /*If this is the next expected packet to be decompressed, send this packet 
     * decompression */

    if (expected_pkt)
    {
        if (hi_util_in_bounds(start, end, ptr))
            iRet = hi_server_decompress(Session, sd, ptr, end, &body_ptr, 0, 0);
    }
    else
#endif
    {
        iRet = hi_server_extract_status_code(start,ptr,end , &stat_code_ptr);

        if ( iRet == STAT_END )
        {
            Server->response.status_code = stat_code_ptr.uri;
            Server->response.status_code_size = stat_code_ptr.uri_end - stat_code_ptr.uri;
            if ( (int)Server->response.status_code_size <= 0)
            {
                CLR_SERVER_STAT(Server);
            }
            else
            {
                iRet = hi_server_extract_status_msg(start, stat_code_ptr.uri_end , 
                        end, &stat_msg_ptr);
    
                if ( stat_msg_ptr.uri )
                {
                    Server->response.status_msg = stat_msg_ptr.uri;
                    Server->response.status_msg_size = stat_msg_ptr.uri_end - stat_msg_ptr.uri;
                    if ((int)Server->response.status_msg_size <= 0)
                    {
                        CLR_SERVER_STAT(Server);
                    }
                    else
                    {
                        ptr =  hi_server_extract_header(Session, ServerConf, &header_ptr, 
                                stat_msg_ptr.uri_end , end, parse_cont_encoding );
                    }
                }
                else
                {
                    CLR_SERVER_STAT(Server);
                }
            }
     
            if (header_ptr.header.uri)
            {
                Server->response.header_raw = header_ptr.header.uri;
                Server->response.header_raw_size = 
                    header_ptr.header.uri_end - header_ptr.header.uri;
                if ((int)Server->response.header_raw_size <= 0)
                {
                    CLR_SERVER_HEADER(Server);
                }
                else
                {
                    hi_stats.resp_headers++;
                    Server->response.header_norm = header_ptr.header.uri;
                    if (header_ptr.cookie.cookie)
                    {
                        hi_stats.resp_cookies++;
                        Server->response.cookie.cookie = header_ptr.cookie.cookie;
                        Server->response.cookie.cookie_end = header_ptr.cookie.cookie_end;
                        Server->response.cookie.next = header_ptr.cookie.next;
                    }
                    else
                    {
                        Server->response.cookie.cookie = NULL;
                        Server->response.cookie.cookie_end = NULL;
                        Server->response.cookie.next = NULL;
                    }
#ifdef ZLIB
                    if( header_ptr.content_encoding.compress_fmt )
                    {
                        hi_stats.gzip_pkts++;
                        if (sd != NULL)
                        {
                            /* We've got gzip data - grab buffer from mempool and attach
                             * to session data if server is configured to do so */
                            if (sd->decomp_state == NULL)
                                SetGzipBuffers(sd, Session);

                            if (sd->decomp_state != NULL)
                            {
                                sd->decomp_state->decompress_data = 1;
                                sd->decomp_state->compress_fmt = 
                                    header_ptr.content_encoding.compress_fmt;

                                if (p->packet_flags & PKT_STREAM_INSERT)
                                {
                                    sd->decomp_state->inspect_reassembled = 1;
                                }
                                else
                                {
                                    expected_pkt = 1;
                                    sd->decomp_state->next_seq = ntohl(p->tcph->th_seq) + p->dsize;
                                    if (hi_util_in_bounds(start, end, header_ptr.header.uri_end + 1))
                                    {
                                        iRet = hi_server_decompress(Session, sd, header_ptr.header.uri_end + 1,
                                            end, &body_ptr, header_ptr.content_len.len, 1);
                                    }
                                }
                            }
                        }
                    }
                    else
#endif
                    {
                        if (hi_util_in_bounds(start, end, header_ptr.header.uri_end + 1))
                        {
                            body_ptr.uri = header_ptr.header.uri_end + 1;
                            body_ptr.uri_end = end;
                            iRet = hi_server_extract_body(Session, ServerConf, 
                                    header_ptr.header.uri_end + 1, end, &body_ptr, header_ptr.content_len.len);
                        }
                    }

                }

            }
            else
            {
                CLR_SERVER_HEADER(Server);

            }
        }
        else
        {
            CLR_SERVER_STAT(Server);
        }
    }

    if( body_ptr.uri )
    {
        Server->response.body = body_ptr.uri;
        Server->response.body_size = body_ptr.uri_end - body_ptr.uri;
        if( Server->response.body_size > 0)
        {
#ifdef ZLIB
            if(expected_pkt)
            {
                if ( Server->response.body_size < DECODE_BLEN )
                {
                    alt_dsize = Server->response.body_size;
                }
                else
                {
                    alt_dsize = DECODE_BLEN;
                }
                p->packet_flags |= PKT_ALT_DECODE;
                p->data_flags |= DATA_FLAGS_GZIP;
                p->alt_dsize = alt_dsize;
                status = SafeMemcpy(DecodeBuffer, Server->response.body,
                        alt_dsize, DecodeBuffer, DecodeBuffer + sizeof(DecodeBuffer));
                if( status != SAFEMEM_SUCCESS  )
                    return HI_MEM_ALLOC_FAIL;
            }
            else
#endif
            {
                p->packet_flags |= PKT_HTTP_RESP_BODY;
            }
        }

    }

    return HI_SUCCESS;
}

int ServerInspection(HI_SESSION *Session, Packet *p, HttpSessionData *hsd)
{
    int iRet;

    if ((p->data == NULL) || (p->dsize == 0))
    {
        return HI_INVALID_ARG;
    }

    if ( Session->server_conf->inspect_response )
    {
        iRet = HttpResponseInspection(Session, p, p->data, p->dsize, hsd);
    }
    else
    {
        iRet = IsHttpServerData(&Session->server, p->data, p->dsize,
                Session->server_conf->server_flow_depth);
    }

    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}

int hi_server_inspection(void *S, Packet *p, HttpSessionData *hsd)
{
    HI_SESSION *Session;

    int iRet;

    if(!S )
    {
        return HI_INVALID_ARG;
    }

    Session = (HI_SESSION *)S;

    /*
    **  Let's inspect the server response.
    */
    iRet = ServerInspection(Session, p, hsd);
    if (iRet)
    {
        return iRet;
    }

    return HI_SUCCESS;
}
