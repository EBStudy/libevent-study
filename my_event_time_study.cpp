//
// Created by LQYHE on 2021/1/22.
//


#include "libevent/include/event2/event.h"
#include "libevent/include/event2/event_struct.h"
#include "libevent/include/event2/util.h"

struct timeval lasttime;

int event_is_persistent;

static void timeout_cb(evutil_socket_t fd, short sevent, void *arg)
{
    timeval newtime, difference;
    event *timeout = static_cast<event*>( arg);
    double elapsed;

    evutil_gettimeofday(&newtime, NULL);
    evutil_timersub(&newtime, &lasttime, &difference);
    elapsed = difference.tv_sec +
        (difference.tv_usec / 1.0e6);

    printf("timeout_cb called at %d: %.3f seconds elapsed.\n",
           (int) newtime.tv_sec, elapsed);
    lasttime = newtime;

    if (!event_is_persistent) {
        struct timeval tv;
        evutil_timerclear(&tv);
        tv.tv_sec = 2;
        event_add(timeout, &tv);
    }
    event_del(timeout);
}

int main(int argc, char *argv[])
{

    auto *event_base = event_base_new();
    event timeout;
    timeval tv;
    event_assign(&timeout, event_base, -1, EV_PERSIST,timeout_cb,(void*)&timeout);
    evutil_timerclear(&tv);
    tv.tv_sec = 2;
    event_add(&timeout, &tv);

    evutil_gettimeofday(&lasttime, NULL);

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

//    event_base_dispatch(event_base);
    event_base_loop(event_base,EVLOOP_NO_EXIT_ON_EMPTY);
    return 0;
}