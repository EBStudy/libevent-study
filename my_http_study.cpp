//
// Created by LQYHE on 2021/1/25.
//


// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "openssl/err.h"
#include "event2/bufferevent_ssl.h"
#include "event2/bufferevent.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

extern void
bufferevent_openssl_set_allow_dirty_shutdown(struct bufferevent *bev,
                                             int allow_dirty_shutdown);
extern unsigned long
bufferevent_get_openssl_error(struct bufferevent *bev);
static void
http_request_done(struct evhttp_request *req, void *ctx)
{
    char buffer[256];
    int nread;

    if (!req || !evhttp_request_get_response_code(req)) {
        /* If req is NULL, it means an error occurred, but
         * sadly we are mostly left guessing what the error
         * might have been.  We'll do our best... */
        struct bufferevent *bev = (struct bufferevent *) ctx;
        unsigned long oslerr;
        int printed_err = 0;
        int errcode = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "some request failed - no idea which one though!\n");
        /* Print out the OpenSSL error queue that libevent
         * squirreled away for us, if any. */
        while ((oslerr = bufferevent_get_openssl_error(bev))) {
            ERR_error_string_n(oslerr, buffer, sizeof(buffer));
            fprintf(stderr, "%s\n", buffer);
            printed_err = 1;
        }
        /* If the OpenSSL error queue was empty, maybe it was a
         * socket error; let's try printing that. */
        if (! printed_err)
            fprintf(stderr, "socket error = %s (%d)\n",
                    evutil_socket_error_to_string(errcode),
                    errcode);
        return;
    }

    fprintf(stderr, "Response line: %d %s\n",
            evhttp_request_get_response_code(req),
            evhttp_request_get_response_code_line(req));

    while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
                                    buffer, sizeof(buffer)))
        > 0) {
        /* These are just arbitrary chunks of 256 bytes.
         * They are not lines, so we can't treat them as such. */
        fwrite(buffer, nread, 1, stdout);
    }
}

int main(int argc,char* argv[])
{
    auto http_arg = evhttp_uri_parse("https:www.baidu.com");
    auto base = event_base_new();
    auto bev = bufferevent_socket_new(base,-1,BEV_OPT_CLOSE_ON_FREE);
    if(!bev)
    {
        return -2;
    }
    bufferevent_openssl_set_allow_dirty_shutdown(bev,1);
    auto evcon = evhttp_connection_base_bufferevent_new(base,NULL,bev,evhttp_uri_get_host(http_arg),evhttp_uri_get_port(http_arg));
    if(!evcon)
    {
        return -3;
    }
    auto req = evhttp_request_new(http_request_done,bev);
    if(!req)
    {
        return -4;
    }
    auto output_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(output_headers, "Host", evhttp_uri_get_host(http_arg));
    evhttp_add_header(output_headers, "Connection", "close");
    auto r = evhttp_make_request(evcon,req,EVHTTP_REQ_GET,"https:www.baidu.com");
    if(r != 0)
    {
        return -5;
    }
    event_base_dispatch(base);



    return 0;
}