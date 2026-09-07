/*
 * Unix library functions
 *
 * Copyright (C) 1993,1994,1996,1997 John Brezak, Erik Bos, Alex Korobka.
 * Copyright (C) 2001 Stefan Leichter
 * Copyright (C) 2004 Hans Leidekker
 * Copyright (C) 2005 Marcus Meissner
 * Copyright (C) 2006-2008 Kai Blin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
# define if_indextoname unix_if_indextoname
# define if_nametoindex unix_if_nametoindex
# include <net/if.h>
# undef if_indextoname
# undef if_nametoindex
#endif
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#include <poll.h>

#ifdef HAVE_NETIPX_IPX_H
# include <netipx/ipx.h>
# define HAS_IPX
#elif defined(HAVE_LINUX_IPX_H)
# ifdef HAVE_ASM_TYPES_H
#  include <asm/types.h>
# endif
# ifdef HAVE_LINUX_TYPES_H
#  include <linux/types.h>
# endif
# include <linux/ipx.h>
# ifdef SOL_IPX
#  define HAS_IPX
# endif
#endif

#ifdef HAVE_LINUX_IRDA_H
# ifdef HAVE_LINUX_TYPES_H
#  include <linux/types.h>
# endif
# include <linux/irda.h>
# define HAS_IRDA
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winerror.h"
#include "winternl.h"
#define USE_WS_PREFIX
#include "winsock2.h"
#include "ws2tcpip.h"
#include "wsipx.h"
#include "af_irda.h"
#include "wine/debug.h"

#include "ws2_32_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(winsock);
WINE_DECLARE_DEBUG_CHANNEL(winediag);

#ifndef HAVE_LINUX_GETHOSTBYNAME_R_6
static pthread_mutex_t host_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define MAP(x) {WS_ ## x, x}

static const int addrinfo_flag_map[][2] =
{
    MAP( AI_PASSIVE ),
    MAP( AI_CANONNAME ),
    MAP( AI_NUMERICHOST ),
#ifdef AI_NUMERICSERV
    MAP( AI_NUMERICSERV ),
#endif
#ifdef AI_V4MAPPED
    MAP( AI_V4MAPPED ),
#endif
#ifdef AI_ALL
    MAP( AI_ALL ),
#endif
    MAP( AI_ADDRCONFIG ),
};

static const int nameinfo_flag_map[][2] =
{
    MAP( NI_DGRAM ),
    MAP( NI_NAMEREQD ),
    MAP( NI_NOFQDN ),
    MAP( NI_NUMERICHOST ),
    MAP( NI_NUMERICSERV ),
};

static const int family_map[][2] =
{
    MAP( AF_UNSPEC ),
    MAP( AF_INET ),
    MAP( AF_INET6 ),
#ifdef AF_IPX
    MAP( AF_IPX ),
#endif
#ifdef AF_IRDA
    MAP( AF_IRDA ),
#endif
};

static const int socktype_map[][2] =
{
    MAP( SOCK_STREAM ),
    MAP( SOCK_DGRAM ),
    MAP( SOCK_RAW ),
};

static const int ip_protocol_map[][2] =
{
    MAP( IPPROTO_IP ),
    MAP( IPPROTO_TCP ),
    MAP( IPPROTO_UDP ),
    MAP( IPPROTO_IPV6 ),
    MAP( IPPROTO_ICMP ),
    MAP( IPPROTO_IGMP ),
    MAP( IPPROTO_RAW ),
    {WS_IPPROTO_IPV4, IPPROTO_IPIP},
};

#undef MAP

static pthread_once_t hash_init_once = PTHREAD_ONCE_INIT;
static BYTE byte_hash[256];

static void init_hash(void)
{
    unsigned i, index;
    NTSTATUS status;
    BYTE *buf, tmp;
    ULONG buf_len;

    for (i = 0; i < sizeof(byte_hash); ++i)
        byte_hash[i] = i;

    buf_len = sizeof(SYSTEM_INTERRUPT_INFORMATION) * NtCurrentTeb()->Peb->NumberOfProcessors;
    if (!(buf = malloc( buf_len )))
    {
        ERR( "No memory.\n" );
        return;
    }

    for (i = 0; i < sizeof(byte_hash) - 1; ++i)
    {
        if (!(i % buf_len) && (status = NtQuerySystemInformation( SystemInterruptInformation, buf,
                                                                  buf_len, &buf_len )))
        {
            ERR( "Failed to get random bytes.\n" );
            free( buf );
            return;
        }
        index = i + buf[i % buf_len] % (sizeof(byte_hash) - i);
        tmp = byte_hash[index];
        byte_hash[index] = byte_hash[i];
        byte_hash[i] = tmp;
    }
    free( buf );
}

static void hash_random( BYTE *d, const BYTE *s, unsigned int len )
{
    unsigned int i;

    for (i = 0; i < len; ++i)
        d[i] = byte_hash[s[i]];
}

static int addrinfo_flags_from_unix( int flags )
{
    int ws_flags = 0;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(addrinfo_flag_map); ++i)
    {
        if (flags & addrinfo_flag_map[i][1])
        {
            ws_flags |= addrinfo_flag_map[i][0];
            flags &= ~addrinfo_flag_map[i][1];
        }
    }

    if (flags)
        FIXME( "unhandled flags %#x\n", flags );
    return ws_flags;
}

static int addrinfo_flags_to_unix( int flags )
{
    int unix_flags = 0;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(addrinfo_flag_map); ++i)
    {
        if (flags & addrinfo_flag_map[i][0])
        {
            unix_flags |= addrinfo_flag_map[i][1];
            flags &= ~addrinfo_flag_map[i][0];
        }
    }

    if (flags)
        FIXME( "unhandled flags %#x\n", flags );
    return unix_flags;
}

static int nameinfo_flags_to_unix( int flags )
{
    int unix_flags = 0;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(nameinfo_flag_map); ++i)
    {
        if (flags & nameinfo_flag_map[i][0])
        {
            unix_flags |= nameinfo_flag_map[i][1];
            flags &= ~nameinfo_flag_map[i][0];
        }
    }

    if (flags)
        FIXME( "unhandled flags %#x\n", flags );
    return unix_flags;
}

static int family_from_unix( int family )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(family_map); ++i)
    {
        if (family == family_map[i][1])
            return family_map[i][0];
    }

    FIXME( "unhandled family %u\n", family );
    return -1;
}

static int family_to_unix( int family )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(family_map); ++i)
    {
        if (family == family_map[i][0])
            return family_map[i][1];
    }

    FIXME( "unhandled family %u\n", family );
    return -1;
}

static int socktype_from_unix( int type )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(socktype_map); ++i)
    {
        if (type == socktype_map[i][1])
            return socktype_map[i][0];
    }

    FIXME( "unhandled type %u\n", type );
    return -1;
}

static int socktype_to_unix( int type )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(socktype_map); ++i)
    {
        if (type == socktype_map[i][0])
            return socktype_map[i][1];
    }

    FIXME( "unhandled type %u\n", type );
    return -1;
}

static int protocol_from_unix( int protocol )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ip_protocol_map); ++i)
    {
        if (protocol == ip_protocol_map[i][1])
            return ip_protocol_map[i][0];
    }

    if (protocol >= WS_NSPROTO_IPX && protocol <= WS_NSPROTO_IPX + 255)
        return protocol;

    FIXME( "unhandled protocol %u\n", protocol );
    return -1;
}

static int protocol_to_unix( int protocol )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ip_protocol_map); ++i)
    {
        if (protocol == ip_protocol_map[i][0])
            return ip_protocol_map[i][1];
    }

    if (protocol >= WS_NSPROTO_IPX && protocol <= WS_NSPROTO_IPX + 255)
        return protocol;

    FIXME( "unhandled protocol %u\n", protocol );
    return -1;
}

static unsigned int errno_from_unix( int err )
{
    switch (err)
    {
        case EINTR:             return WSAEINTR;
        case EBADF:             return WSAEBADF;
        case EPERM:
        case EACCES:            return WSAEACCES;
        case EFAULT:            return WSAEFAULT;
        case EINVAL:            return WSAEINVAL;
        case EMFILE:            return WSAEMFILE;
        case EINPROGRESS:
        case EWOULDBLOCK:       return WSAEWOULDBLOCK;
        case EALREADY:          return WSAEALREADY;
        case ENOTSOCK:          return WSAENOTSOCK;
        case EDESTADDRREQ:      return WSAEDESTADDRREQ;
        case EMSGSIZE:          return WSAEMSGSIZE;
        case EPROTOTYPE:        return WSAEPROTOTYPE;
        case ENOPROTOOPT:       return WSAENOPROTOOPT;
        case EPROTONOSUPPORT:   return WSAEPROTONOSUPPORT;
        case ESOCKTNOSUPPORT:   return WSAESOCKTNOSUPPORT;
        case EOPNOTSUPP:        return WSAEOPNOTSUPP;
        case EPFNOSUPPORT:      return WSAEPFNOSUPPORT;
        case EAFNOSUPPORT:      return WSAEAFNOSUPPORT;
        case EADDRINUSE:        return WSAEADDRINUSE;
        case EADDRNOTAVAIL:     return WSAEADDRNOTAVAIL;
        case ENETDOWN:          return WSAENETDOWN;
        case ENETUNREACH:       return WSAENETUNREACH;
        case ENETRESET:         return WSAENETRESET;
        case ECONNABORTED:      return WSAECONNABORTED;
        case EPIPE:
        case ECONNRESET:        return WSAECONNRESET;
        case ENOBUFS:           return WSAENOBUFS;
        case EISCONN:           return WSAEISCONN;
        case ENOTCONN:          return WSAENOTCONN;
        case ESHUTDOWN:         return WSAESHUTDOWN;
        case ETOOMANYREFS:      return WSAETOOMANYREFS;
        case ETIMEDOUT:         return WSAETIMEDOUT;
        case ECONNREFUSED:      return WSAECONNREFUSED;
        case ELOOP:             return WSAELOOP;
        case ENAMETOOLONG:      return WSAENAMETOOLONG;
        case EHOSTDOWN:         return WSAEHOSTDOWN;
        case EHOSTUNREACH:      return WSAEHOSTUNREACH;
        case ENOTEMPTY:         return WSAENOTEMPTY;
#ifdef EPROCLIM
        case EPROCLIM:          return WSAEPROCLIM;
#endif
#ifdef EUSERS
        case EUSERS:            return WSAEUSERS;
#endif
#ifdef EDQUOT
        case EDQUOT:            return WSAEDQUOT;
#endif
#ifdef ESTALE
        case ESTALE:            return WSAESTALE;
#endif
#ifdef EREMOTE
        case EREMOTE:           return WSAEREMOTE;
#endif
        default:
            FIXME( "unknown error: %s\n", strerror( err ) );
            return WSAEFAULT;
    }
}

static UINT host_errno_from_unix( int err )
{
    WARN( "%d\n", err );

    switch (err)
    {
        case HOST_NOT_FOUND:    return WSAHOST_NOT_FOUND;
        case TRY_AGAIN:         return WSATRY_AGAIN;
        case NO_RECOVERY:       return WSANO_RECOVERY;
        case NO_DATA:           return WSANO_DATA;
        case ENOBUFS:           return WSAENOBUFS;
        case 0:                 return 0;
        default:
            WARN( "Unknown h_errno %d!\n", err );
            return WSAEOPNOTSUPP;
    }
}

static int addrinfo_err_from_unix( int err )
{
    switch (err)
    {
        case 0:             return 0;
        case EAI_AGAIN:     return WS_EAI_AGAIN;
        case EAI_BADFLAGS:  return WS_EAI_BADFLAGS;
        case EAI_FAIL:      return WS_EAI_FAIL;
        case EAI_FAMILY:    return WS_EAI_FAMILY;
        case EAI_MEMORY:    return WS_EAI_MEMORY;
        /* EAI_NODATA is deprecated, but still used by Windows and Linux. We map
         * the newer EAI_NONAME to EAI_NODATA for now until Windows changes too. */
#ifdef EAI_NODATA
        case EAI_NODATA:    return WS_EAI_NODATA;
#endif
#ifdef EAI_NONAME
        case EAI_NONAME:    return WS_EAI_NODATA;
#endif
        case EAI_SERVICE:   return WS_EAI_SERVICE;
        case EAI_SOCKTYPE:  return WS_EAI_SOCKTYPE;
        case EAI_SYSTEM:
            if (errno == EBUSY) ERR_(winediag)("getaddrinfo() returned EBUSY. You may be missing a libnss plugin\n");
            /* some broken versions of glibc return EAI_SYSTEM and set errno to
             * 0 instead of returning EAI_NONAME */
            return errno ? errno_from_unix( errno ) : WS_EAI_NONAME;

        default:
            FIXME( "unhandled error %d\n", err );
            return err;
    }
}

union unix_sockaddr
{
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
#ifdef HAS_IPX
    struct sockaddr_ipx ipx;
#endif
#ifdef HAS_IRDA
    struct sockaddr_irda irda;
#endif
};

/* different from the version in ntdll and server; it does not return failure if
 * given a short buffer */
static int sockaddr_from_unix( const union unix_sockaddr *uaddr, struct WS_sockaddr *wsaddr, socklen_t wsaddrlen )
{
    memset( wsaddr, 0, wsaddrlen );

    switch (uaddr->addr.sa_family)
    {
    case AF_INET:
    {
        struct WS_sockaddr_in win = {0};

        if (wsaddrlen >= sizeof(win))
        {
            win.sin_family = WS_AF_INET;
            win.sin_port = uaddr->in.sin_port;
            memcpy( &win.sin_addr, &uaddr->in.sin_addr, sizeof(win.sin_addr) );
            memcpy( wsaddr, &win, sizeof(win) );
        }
        return sizeof(win);
    }

    case AF_INET6:
    {
        struct WS_sockaddr_in6 win = {0};

        if (wsaddrlen >= sizeof(win))
        {
            win.sin6_family = WS_AF_INET6;
            win.sin6_port = uaddr->in6.sin6_port;
            win.sin6_flowinfo = uaddr->in6.sin6_flowinfo;
            memcpy( &win.sin6_addr, &uaddr->in6.sin6_addr, sizeof(win.sin6_addr) );
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
            win.sin6_scope_id = uaddr->in6.sin6_scope_id;
#endif
            memcpy( wsaddr, &win, sizeof(win) );
        }
        return sizeof(win);
    }

#ifdef HAS_IPX
    case AF_IPX:
    {
        struct WS_sockaddr_ipx win = {0};

        if (wsaddrlen >= sizeof(win))
        {
            win.sa_family = WS_AF_IPX;
            memcpy( win.sa_netnum, &uaddr->ipx.sipx_network, sizeof(win.sa_netnum) );
            memcpy( win.sa_nodenum, &uaddr->ipx.sipx_node, sizeof(win.sa_nodenum) );
            win.sa_socket = uaddr->ipx.sipx_port;
            memcpy( wsaddr, &win, sizeof(win) );
        }
        return sizeof(win);
    }
#endif

#ifdef HAS_IRDA
    case AF_IRDA:
    {
        SOCKADDR_IRDA win;

        if (wsaddrlen >= sizeof(win))
        {
            win.irdaAddressFamily = WS_AF_IRDA;
            memcpy( win.irdaDeviceID, &uaddr->irda.sir_addr, sizeof(win.irdaDeviceID) );
            if (uaddr->irda.sir_lsap_sel != LSAP_ANY)
                snprintf( win.irdaServiceName, sizeof(win.irdaServiceName), "LSAP-SEL%u", uaddr->irda.sir_lsap_sel );
            else
                memcpy( win.irdaServiceName, uaddr->irda.sir_name, sizeof(win.irdaServiceName) );
            memcpy( wsaddr, &win, sizeof(win) );
        }
        return sizeof(win);
    }
#endif

    case AF_UNSPEC:
        return 0;

    default:
        FIXME( "unknown address family %d\n", uaddr->addr.sa_family );
        return 0;
    }
}

static socklen_t sockaddr_to_unix( const struct WS_sockaddr *wsaddr, int wsaddrlen, union unix_sockaddr *uaddr )
{
    memset( uaddr, 0, sizeof(*uaddr) );

    switch (wsaddr->sa_family)
    {
    case WS_AF_INET:
    {
        struct WS_sockaddr_in win = {0};

        if (wsaddrlen < sizeof(win)) return 0;
        memcpy( &win, wsaddr, sizeof(win) );
        uaddr->in.sin_family = AF_INET;
        uaddr->in.sin_port = win.sin_port;
        memcpy( &uaddr->in.sin_addr, &win.sin_addr, sizeof(win.sin_addr) );
        return sizeof(uaddr->in);
    }

    case WS_AF_INET6:
    {
        struct WS_sockaddr_in6 win = {0};

        if (wsaddrlen < sizeof(win)) return 0;
        memcpy( &win, wsaddr, sizeof(win) );
        uaddr->in6.sin6_family = AF_INET6;
        uaddr->in6.sin6_port = win.sin6_port;
        uaddr->in6.sin6_flowinfo = win.sin6_flowinfo;
        memcpy( &uaddr->in6.sin6_addr, &win.sin6_addr, sizeof(win.sin6_addr) );
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
        uaddr->in6.sin6_scope_id = win.sin6_scope_id;
#endif
        return sizeof(uaddr->in6);
    }

#ifdef HAS_IPX
    case WS_AF_IPX:
    {
        struct WS_sockaddr_ipx win = {0};

        if (wsaddrlen < sizeof(win)) return 0;
        memcpy( &win, wsaddr, sizeof(win) );
        uaddr->ipx.sipx_family = AF_IPX;
        memcpy( &uaddr->ipx.sipx_network, win.sa_netnum, sizeof(win.sa_netnum) );
        memcpy( &uaddr->ipx.sipx_node, win.sa_nodenum, sizeof(win.sa_nodenum) );
        uaddr->ipx.sipx_port = win.sa_socket;
        return sizeof(uaddr->ipx);
    }
#endif

#ifdef HAS_IRDA
    case WS_AF_IRDA:
    {
        SOCKADDR_IRDA win = {0};
        unsigned int lsap_sel;

        if (wsaddrlen < sizeof(win)) return 0;
        memcpy( &win, wsaddr, sizeof(win) );
        uaddr->irda.sir_family = AF_IRDA;
        if (sscanf( win.irdaServiceName, "LSAP-SEL%u", &lsap_sel ) == 1)
            uaddr->irda.sir_lsap_sel = lsap_sel;
        else
        {
            uaddr->irda.sir_lsap_sel = LSAP_ANY;
            memcpy( uaddr->irda.sir_name, win.irdaServiceName, sizeof(win.irdaServiceName) );
        }
        memcpy( &uaddr->irda.sir_addr, win.irdaDeviceID, sizeof(win.irdaDeviceID) );
        return sizeof(uaddr->irda);
    }
#endif

    case WS_AF_UNSPEC:
        switch (wsaddrlen)
        {
        default: /* likely an ipv4 address */
        case sizeof(struct WS_sockaddr_in):
            return sizeof(uaddr->in);

#ifdef HAS_IPX
        case sizeof(struct WS_sockaddr_ipx):
            return sizeof(uaddr->ipx);
#endif

#ifdef HAS_IRDA
        case sizeof(SOCKADDR_IRDA):
            return sizeof(uaddr->irda);
#endif

        case sizeof(struct WS_sockaddr_in6):
            return sizeof(uaddr->in6);
        }

    default:
        FIXME( "unknown address family %u\n", wsaddr->sa_family );
        return 0;
    }
}

static BOOL addrinfo_in_list( const struct WS_addrinfo *list, const struct WS_addrinfo *ai )
{
    const struct WS_addrinfo *cursor = list;
    while (cursor)
    {
        if (ai->ai_flags == cursor->ai_flags &&
            ai->ai_family == cursor->ai_family &&
            ai->ai_socktype == cursor->ai_socktype &&
            ai->ai_protocol == cursor->ai_protocol &&
            ai->ai_addrlen == cursor->ai_addrlen &&
            !memcmp( ai->ai_addr, cursor->ai_addr, ai->ai_addrlen ) &&
            ((ai->ai_canonname && cursor->ai_canonname && !strcmp( ai->ai_canonname, cursor->ai_canonname ))
            || (!ai->ai_canonname && !cursor->ai_canonname)))
        {
            return TRUE;
        }
        cursor = cursor->ai_next;
    }
    return FALSE;
}

static NTSTATUS unix_getaddrinfo( void *args )
{
#ifdef HAVE_GETADDRINFO
    struct getaddrinfo_params *params = args;
    const char *service = params->service;
    const struct WS_addrinfo *hints = params->hints;
    struct addrinfo unix_hints = {0};
    struct addrinfo *unix_info, *src;
    struct WS_addrinfo *dst, *prev = NULL;
    unsigned int needed_size = 0;
    int ret;

    /* servname tweak required by OSX and BSD kernels */
    if (service && !service[0]) service = "0";

    if (hints)
    {
        unix_hints.ai_flags = addrinfo_flags_to_unix( hints->ai_flags );

        if (hints->ai_family)
            unix_hints.ai_family = family_to_unix( hints->ai_family );

        if (hints->ai_socktype)
        {
            if ((unix_hints.ai_socktype = socktype_to_unix( hints->ai_socktype )) < 0)
                return WSAESOCKTNOSUPPORT;
        }

        if (hints->ai_protocol)
            unix_hints.ai_protocol = max( protocol_to_unix( hints->ai_protocol ), 0 );

        /* Windows allows some invalid combinations */
        if (unix_hints.ai_protocol == IPPROTO_TCP
                && unix_hints.ai_socktype != SOCK_STREAM
                && unix_hints.ai_socktype != SOCK_SEQPACKET)
        {
            WARN( "ignoring invalid type %u for TCP\n", unix_hints.ai_socktype );
            unix_hints.ai_socktype = 0;
        }
        else if (unix_hints.ai_protocol == IPPROTO_UDP && unix_hints.ai_socktype != SOCK_DGRAM)
        {
            WARN( "ignoring invalid type %u for UDP\n", unix_hints.ai_socktype );
            unix_hints.ai_socktype = 0;
        }
        else if (unix_hints.ai_protocol >= WS_NSPROTO_IPX && unix_hints.ai_protocol <= WS_NSPROTO_IPX + 255
                && unix_hints.ai_socktype != SOCK_DGRAM)
        {
            WARN( "ignoring invalid type %u for IPX\n", unix_hints.ai_socktype );
            unix_hints.ai_socktype = 0;
        }
        else if (unix_hints.ai_protocol == IPPROTO_IPV6)
        {
            WARN( "ignoring protocol IPv6\n" );
            unix_hints.ai_protocol = 0;
        }
    }

    ret = getaddrinfo( params->node, service, hints ? &unix_hints : NULL, &unix_info );
    if (ret)
        return addrinfo_err_from_unix( ret );

    for (src = unix_info; src != NULL; src = src->ai_next)
    {
        needed_size += sizeof(struct WS_addrinfo);
        if (src->ai_canonname)
            needed_size += strlen( src->ai_canonname ) + 1;
        needed_size += sockaddr_from_unix( (const union unix_sockaddr *)src->ai_addr, NULL, 0 );
    }

    if (*params->size < needed_size)
    {
        *params->size = needed_size;
        freeaddrinfo( unix_info );
        return ERROR_INSUFFICIENT_BUFFER;
    }

    dst = params->info;

    memset( params->info, 0, needed_size );

    for (src = unix_info; src != NULL; src = src->ai_next)
    {
        void *next = dst + 1;

        dst->ai_flags = addrinfo_flags_from_unix( src->ai_flags );
        dst->ai_family = family_from_unix( src->ai_family );
        if (hints)
        {
            dst->ai_socktype = hints->ai_socktype;
            dst->ai_protocol = hints->ai_protocol;
        }
        else
        {
            dst->ai_socktype = socktype_from_unix( src->ai_socktype );
            dst->ai_protocol = protocol_from_unix( src->ai_protocol );
        }
        if (src->ai_canonname)
        {
            size_t len = strlen( src->ai_canonname ) + 1;

            dst->ai_canonname = next;
            memcpy( dst->ai_canonname, src->ai_canonname, len );
            next = dst->ai_canonname + len;
        }

        dst->ai_addrlen = sockaddr_from_unix( (const union unix_sockaddr *)src->ai_addr, NULL, 0 );
        dst->ai_addr = next;
        sockaddr_from_unix( (const union unix_sockaddr *)src->ai_addr, dst->ai_addr, dst->ai_addrlen );
        dst->ai_next = NULL;
        next = (char *)dst->ai_addr + dst->ai_addrlen;

        if (dst == params->info || !addrinfo_in_list( params->info, dst ))
        {
            if (prev)
                prev->ai_next = dst;
            prev = dst;
            dst = next;
        }
    }

    freeaddrinfo( unix_info );
    return 0;
#else
    FIXME( "getaddrinfo() not found during build time\n" );
    return WS_EAI_FAIL;
#endif
}


static int hostent_from_unix( const struct hostent *unix_host, struct WS_hostent *host, unsigned int *const size )
{
    unsigned int needed_size = sizeof( struct WS_hostent ), alias_count = 0, addr_count = 0, i;
    char *p;

    needed_size += strlen( unix_host->h_name ) + 1;

    for (alias_count = 0; unix_host->h_aliases[alias_count] != NULL; ++alias_count)
        needed_size += sizeof(char *) + strlen( unix_host->h_aliases[alias_count] ) + 1;
    needed_size += sizeof(char *); /* null terminator */

    for (addr_count = 0; unix_host->h_addr_list[addr_count] != NULL; ++addr_count)
        needed_size += sizeof(char *) + unix_host->h_length;
    needed_size += sizeof(char *); /* null terminator */

    if (*size < needed_size)
    {
        *size = needed_size;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset( host, 0, needed_size );

    /* arrange the memory in the same order as windows >= XP */

    host->h_addrtype = family_from_unix( unix_host->h_addrtype );
    host->h_length = unix_host->h_length;

    p = (char *)(host + 1);
    host->h_aliases = (char **)p;
    p += (alias_count + 1) * sizeof(char *);
    host->h_addr_list = (char **)p;
    p += (addr_count + 1) * sizeof(char *);

    for (i = 0; i < addr_count; ++i)
    {
        host->h_addr_list[i] = p;
        memcpy( host->h_addr_list[i], unix_host->h_addr_list[i], unix_host->h_length );
        p += unix_host->h_length;
    }

    for (i = 0; i < alias_count; ++i)
    {
        size_t len = strlen( unix_host->h_aliases[i] ) + 1;

        host->h_aliases[i] = p;
        memcpy( host->h_aliases[i], unix_host->h_aliases[i], len );
        p += len;
    }

    host->h_name = p;
    strcpy( host->h_name, unix_host->h_name );

    return 0;
}


static NTSTATUS unix_gethostbyaddr( void *args )
{
    struct gethostbyaddr_params *params = args;
    const void *addr = params->addr;
    const struct in_addr loopback = { htonl( INADDR_LOOPBACK ) };
    int unix_family = family_to_unix( params->family );
    struct hostent *unix_host;
    int ret;

    if (params->family == WS_AF_INET && params->len == 4 && !memcmp( addr, magic_loopback_addr, 4 ))
        addr = &loopback;

#ifdef HAVE_LINUX_GETHOSTBYNAME_R_6
    {
        char *unix_buffer, *new_buffer;
        struct hostent stack_host;
        int unix_size = 1024;
        int locerr;

        if (!(unix_buffer = malloc( unix_size )))
            return WSAENOBUFS;

        while (gethostbyaddr_r( addr, params->len, unix_family, &stack_host, unix_buffer,
                                unix_size, &unix_host, &locerr ) == ERANGE)
        {
            unix_size *= 2;
            if (!(new_buffer = realloc( unix_buffer, unix_size )))
            {
                free( unix_buffer );
                return WSAENOBUFS;
            }
            unix_buffer = new_buffer;
        }

        if (!unix_host)
            ret = (locerr < 0 ? errno_from_unix( errno ) : host_errno_from_unix( locerr ));
        else
            ret = hostent_from_unix( unix_host, params->host, params->size );

        free( unix_buffer );
        return ret;
    }
#else
    pthread_mutex_lock( &host_mutex );

    if (!(unix_host = gethostbyaddr( addr, params->len, unix_family )))
    {
        ret = (h_errno < 0 ? errno_from_unix( errno ) : host_errno_from_unix( h_errno ));
        pthread_mutex_unlock( &host_mutex );
        return ret;
    }

    ret = hostent_from_unix( unix_host, params->host, params->size );

    pthread_mutex_unlock( &host_mutex );
    return ret;
#endif
}

static int compare_addrs_hashed( const void *a1, const void *a2, int addr_len )
{
    char a1_hashed[16], a2_hashed[16];

    assert( addr_len <= sizeof(a1_hashed) );
    hash_random( (BYTE *)a1_hashed, a1, addr_len );
    hash_random( (BYTE *)a2_hashed, a2, addr_len );
    return memcmp( a1_hashed, a2_hashed, addr_len );
}

static void sort_addrs_hashed( struct hostent *host )
{
    /* On Unix gethostbyname() may return IP addresses in random order on each call. On Windows the order of
     * IP addresses is not determined as well but it is the same on consequent calls (changes after network
     * resets and probably DNS timeout expiration).
     * Life is Strange Remastered depends on gethostbyname() returning IP addresses in the same order to reuse
     * the established TLS connection and avoid timeouts that happen in game when establishing multiple extra TLS
     * connections.
     * Just sorting the addresses would break server load balancing provided by gethostbyname(), so randomize the
     * sort once per process. */
    unsigned int i, j;
    char *tmp;

    pthread_once( &hash_init_once, init_hash );

    for (i = 0; host->h_addr_list[i]; ++i)
    {
        for (j = i + 1; host->h_addr_list[j]; ++j)
        {
            if (compare_addrs_hashed( host->h_addr_list[j], host->h_addr_list[i], host->h_length ) < 0)
            {
                tmp = host->h_addr_list[j];
                host->h_addr_list[j] = host->h_addr_list[i];
                host->h_addr_list[i] = tmp;
            }
        }
    }
}

#ifdef HAVE_LINUX_GETHOSTBYNAME_R_6
static NTSTATUS unix_gethostbyname( void *args )
{
    struct gethostbyname_params *params = args;
    struct hostent stack_host, *unix_host;
    char *unix_buffer, *new_buffer;
    int unix_size = 1024;
    int locerr;
    int ret;

    if (!(unix_buffer = malloc( unix_size )))
        return WSAENOBUFS;

    while (gethostbyname_r( params->name, &stack_host, unix_buffer, unix_size, &unix_host, &locerr ) == ERANGE)
    {
        unix_size *= 2;
        if (!(new_buffer = realloc( unix_buffer, unix_size )))
        {
            free( unix_buffer );
            return WSAENOBUFS;
        }
        unix_buffer = new_buffer;
    }

    if (!unix_host)
    {
        ret = (locerr < 0 ? errno_from_unix( errno ) : host_errno_from_unix( locerr ));
    }
    else
    {
        sort_addrs_hashed( unix_host );
        ret = hostent_from_unix( unix_host, params->host, params->size );
    }

    free( unix_buffer );
    return ret;
}
#else
static NTSTATUS unix_gethostbyname( void *args )
{
    struct gethostbyname_params *params = args;
    struct hostent *unix_host;
    int ret;

    pthread_mutex_lock( &host_mutex );

    if (!(unix_host = gethostbyname( params->name )))
    {
        ret = (h_errno < 0 ? errno_from_unix( errno ) : host_errno_from_unix( h_errno ));
        pthread_mutex_unlock( &host_mutex );
        return ret;
    }

    sort_addrs_hashed( unix_host );
    ret = hostent_from_unix( unix_host, params->host, params->size );

    pthread_mutex_unlock( &host_mutex );
    return ret;
}
#endif


static NTSTATUS unix_gethostname( void *args )
{
    struct gethostname_params *params = args;

    if (!gethostname( params->name, params->size ))
        return 0;
    return errno_from_unix( errno );
}


static NTSTATUS unix_getnameinfo( void *args )
{
    struct getnameinfo_params *params = args;
    union unix_sockaddr unix_addr;
    socklen_t unix_addr_len;

    unix_addr_len = sockaddr_to_unix( params->addr, params->addr_len, &unix_addr );

    return addrinfo_err_from_unix( getnameinfo( &unix_addr.addr, unix_addr_len, params->host, params->host_len,
                                                params->serv, params->serv_len,
                                                nameinfo_flags_to_unix( params->flags ) ) );
}


const unixlib_entry_t __wine_unix_call_funcs[] =
{
    unix_getaddrinfo,
    unix_gethostbyaddr,
    unix_gethostbyname,
    unix_gethostname,
    unix_getnameinfo,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == ws_unix_funcs_count );

#ifdef _WIN64

typedef ULONG PTR32;

struct WS_addrinfo32
{
    int   ai_flags;
    int   ai_family;
    int   ai_socktype;
    int   ai_protocol;
    PTR32 ai_addrlen;
    PTR32 ai_canonname;
    PTR32 ai_addr;
    PTR32 ai_next;
};

struct WS_hostent32
{
    PTR32 h_name;
    PTR32 h_aliases;
    short h_addrtype;
    short h_length;
    PTR32 h_addr_list;
};

static NTSTATUS put_addrinfo32( const struct WS_addrinfo *info, struct WS_addrinfo32 *info32,
                                unsigned int *size, PTR32 guest_base )
{
    struct WS_addrinfo32 *dst = info32, *prev = NULL;
    const struct WS_addrinfo *src;
    SIZE_T needed_size = 0;

    for (src = info; src != NULL; src = src->ai_next)
    {
        needed_size += sizeof(struct WS_addrinfo32);
        if (src->ai_canonname) needed_size += strlen( src->ai_canonname ) + 1;
        needed_size += src->ai_addrlen;
    }

    if (needed_size > 0xffffffffu) return WSAENOBUFS;
    if (*size < needed_size)
    {
        *size = needed_size;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset( info32, 0, needed_size );

    for (src = info; src != NULL; src = src->ai_next)
    {
        char *next = (char *)(dst + 1);

        dst->ai_flags = src->ai_flags;
        dst->ai_family = src->ai_family;
        dst->ai_socktype = src->ai_socktype;
        dst->ai_protocol = src->ai_protocol;
        if (src->ai_canonname)
        {
            dst->ai_canonname = guest_base + (ULONG)(next - (char *)info32);
            strcpy( next, src->ai_canonname );
            next += strlen(next) + 1;
        }
        dst->ai_addrlen = src->ai_addrlen;
        dst->ai_addr = guest_base + (ULONG)((char *)next - (char *)info32);
        memcpy( next, src->ai_addr, dst->ai_addrlen );
        next += dst->ai_addrlen;
        if (prev) prev->ai_next = guest_base + (ULONG)((char *)dst - (char *)info32);
        prev = dst;
        dst = (struct WS_addrinfo32 *)next;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS put_hostent32( const struct WS_hostent *host, struct WS_hostent32 *host32,
                               unsigned int *size, PTR32 guest_base )
{
    SIZE_T needed_size = sizeof( struct WS_hostent32 );
    unsigned int alias_count = 0, addr_count = 0, i;
    char *p;
    ULONG *aliases, *addr_list;

    needed_size += strlen( host->h_name ) + 1;

    for (alias_count = 0; host->h_aliases[alias_count] != NULL; ++alias_count)
        needed_size += sizeof(ULONG) + strlen( host->h_aliases[alias_count] ) + 1;
    needed_size += sizeof(ULONG); /* null terminator */

    for (addr_count = 0; host->h_addr_list[addr_count] != NULL; ++addr_count)
        needed_size += sizeof(ULONG) + host->h_length;
    needed_size += sizeof(ULONG); /* null terminator */

    if (needed_size > 0xffffffffu) return WSAENOBUFS;
    if (*size < needed_size)
    {
        *size = needed_size;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset( host32, 0, needed_size );

    /* arrange the memory in the same order as windows >= XP */

    host32->h_addrtype = host->h_addrtype;
    host32->h_length = host->h_length;

    aliases = (ULONG *)(host32 + 1);
    addr_list = aliases + alias_count + 1;
    p = (char *)(addr_list + addr_count + 1);

    host32->h_aliases = guest_base + (ULONG)((char *)aliases - (char *)host32);
    host32->h_addr_list = guest_base + (ULONG)((char *)addr_list - (char *)host32);

    for (i = 0; i < addr_count; ++i)
    {
        addr_list[i] = guest_base + (ULONG)((char *)p - (char *)host32);
        memcpy( p, host->h_addr_list[i], host->h_length );
        p += host->h_length;
    }

    for (i = 0; i < alias_count; ++i)
    {
        size_t len = strlen( host->h_aliases[i] ) + 1;

        aliases[i] = guest_base + (ULONG)((char *)p - (char *)host32);
        memcpy( p, host->h_aliases[i], len );
        p += len;
    }

    host32->h_name = guest_base + (ULONG)((char *)p - (char *)host32);
    strcpy( p, host->h_name );
    return STATUS_SUCCESS;
}


#if defined(__APPLE__) && defined(__aarch64__)
/* Limited high-shadow WoW64 bridge. No guest pointer is passed to libc or
 * retained across calls. Resolver results are flattened into caller memory. */
#define WS32_BUFFER_LIMIT (1024u * 1024u)
#define WS32_STRING_LIMIT 65536u
struct ws32_gai { PTR32 node, service, hints, info, size; };
struct ws32_hba { PTR32 addr; int len, family; PTR32 host, size; };
struct ws32_hbn { PTR32 name, host, size; };
struct ws32_hn { PTR32 name; unsigned int size; };
struct ws32_ni { PTR32 addr; int addr_len; PTR32 host; DWORD host_len; PTR32 serv; DWORD serv_len; int flags; };

static NTSTATUS ws32_pointer( PTR32 guest, SIZE_T size, void **host )
{
    if (!guest || size > 0x100000000ull - guest) return WSAEFAULT;
    if (ntdll_wow64_guest32_to_host( guest, host )) return WSAEFAULT;
    return 0;
}

static NTSTATUS ws32_read( void *dst, PTR32 guest, SIZE_T size )
{
    void *host;
    if (ws32_pointer( guest, size, &host ) || ntdll_wow64_copy_from_user( dst, host, size ))
        return WSAEFAULT;
    return 0;
}

static NTSTATUS ws32_string( PTR32 guest, char **out )
{
    unsigned int used = 0;
    char *copy;
    *out = NULL;
    if (!guest) return 0;
    if (!(copy = malloc( WS32_STRING_LIMIT ))) return WSAENOBUFS;
    while (used < WS32_STRING_LIMIT)
    {
        unsigned int count = min( 4096 - ((guest + used) & 4095), WS32_STRING_LIMIT - used );
        if ((UINT64)guest + used + count > 0x100000000ull || ws32_read( copy + used, guest + used, count ))
        { free( copy ); return WSAEFAULT; }
        if (memchr( copy + used, 0, count )) { *out = copy; return 0; }
        used += count;
    }
    free( copy );
    return WSAEINVAL;
}

/* Probe every output before publication. Overlapping outputs have no useful
 * representation in this ABI and are rejected without publishing either. */
static NTSTATUS ws32_publish( PTR32 first, const void *data, unsigned int bytes,
                              PTR32 second, const void *data2, unsigned int bytes2 )
{
    struct ntdll_wow64_user_write_range ranges[2];
    unsigned int count = 0;
    if (bytes && bytes2 && (UINT64)first < (UINT64)second + bytes2 &&
        (UINT64)second < (UINT64)first + bytes) return WSAEFAULT;
    if (bytes)
    {
        if (ws32_pointer( first, bytes, &ranges[count].dst )) return WSAEFAULT;
        ranges[count].src = data; ranges[count++].size = bytes;
    }
    if (bytes2)
    {
        if (ws32_pointer( second, bytes2, &ranges[count].dst )) return WSAEFAULT;
        ranges[count].src = data2; ranges[count++].size = bytes2;
    }
    if (ntdll_wow64_atomic_writev( ranges, count )) return WSAEFAULT;
    return 0;
}

static NTSTATUS ws32_capacity( PTR32 size, unsigned int *capacity )
{
    void *host;
    if (ws32_read( capacity, size, sizeof(*capacity) ) ||
        ws32_pointer( size, sizeof(*capacity), &host ) ||
        ntdll_wow64_probe_user_write( host, sizeof(*capacity) )) return WSAEFAULT;
    if (*capacity > WS32_BUFFER_LIMIT) return WSAENOBUFS;
    return 0;
}

static NTSTATUS ws32_result( const void *native, BOOL hostent, PTR32 guest,
                             PTR32 guest_size, unsigned int capacity )
{
    unsigned int needed = 0;
    NTSTATUS status;
    void *flat;
    status = hostent ? put_hostent32( native, NULL, &needed, guest ) :
                       put_addrinfo32( native, NULL, &needed, guest );
    if (status != ERROR_INSUFFICIENT_BUFFER) return status ? status : WSAEINVAL;
    if (needed > WS32_BUFFER_LIMIT) return WSAENOBUFS;
    if (capacity < needed)
    {
        status = ws32_publish( guest_size, &needed, sizeof(needed), 0, NULL, 0 );
        return status ? status : ERROR_INSUFFICIENT_BUFFER;
    }
    if ((UINT64)guest + needed > 0x100000000ull || !guest) return WSAEFAULT;
    if (!(flat = malloc( needed ))) return WSAENOBUFS;
    status = hostent ? put_hostent32( native, flat, &needed, guest ) :
                       put_addrinfo32( native, flat, &needed, guest );
    if (!status) status = ws32_publish( guest, flat, needed, guest_size, &needed, sizeof(needed) );
    free( flat );
    return status;
}

static NTSTATUS wow64_unix_getaddrinfo( void *args )
{
    const struct ws32_gai *a = args;
    struct WS_addrinfo hints = {0};
    struct WS_addrinfo32 h;
    struct getaddrinfo_params p = {0};
    unsigned int capacity, native_size = WS32_BUFFER_LIMIT;
    char *node = NULL, *service = NULL;
    NTSTATUS status;
    if ((status = ws32_capacity( a->size, &capacity ))) return status;
    if ((status = ws32_string( a->node, &node )) ||
        (status = ws32_string( a->service, &service ))) goto done;
    if (a->hints)
    {
        if ((status = ws32_read( &h, a->hints, sizeof(h) ))) goto done;
        hints.ai_flags = h.ai_flags; hints.ai_family = h.ai_family;
        hints.ai_socktype = h.ai_socktype; hints.ai_protocol = h.ai_protocol;
        p.hints = &hints;
    }
    p.node = node; p.service = service; p.size = &native_size;
    if (!(p.info = malloc( native_size ))) { status = WSAENOBUFS; goto done; }
    status = unix_getaddrinfo( &p );
    if (!status) status = ws32_result( p.info, FALSE, a->info, a->size, capacity );
    else if (status == ERROR_INSUFFICIENT_BUFFER) status = WSAENOBUFS;
    free( p.info );
done:
    free( node ); free( service );
    return status;
}

static NTSTATUS wow64_unix_gethostbyaddr( void *args )
{
    const struct ws32_hba *a = args;
    struct gethostbyaddr_params p;
    unsigned char address[16];
    unsigned int capacity, native_size = WS32_BUFFER_LIMIT;
    NTSTATUS status;
    if ((a->family != WS_AF_INET || a->len != 4) &&
        (a->family != WS_AF_INET6 || a->len != 16)) return WSAEINVAL;
    if ((status = ws32_capacity( a->size, &capacity )) ||
        (status = ws32_read( address, a->addr, a->len ))) return status;
    p.addr = address; p.len = a->len; p.family = a->family; p.size = &native_size;
    if (!(p.host = malloc( native_size ))) return WSAENOBUFS;
    status = unix_gethostbyaddr( &p );
    if (!status) status = ws32_result( p.host, TRUE, a->host, a->size, capacity );
    else if (status == ERROR_INSUFFICIENT_BUFFER) status = WSAENOBUFS;
    free( p.host );
    return status;
}

static NTSTATUS wow64_unix_gethostbyname( void *args )
{
    const struct ws32_hbn *a = args;
    struct gethostbyname_params p;
    unsigned int capacity, native_size = WS32_BUFFER_LIMIT;
    char *name = NULL;
    NTSTATUS status;
    if ((status = ws32_capacity( a->size, &capacity )) ||
        (status = ws32_string( a->name, &name ))) return status;
    if (!name) return WSAEFAULT;
    p.name = name; p.size = &native_size;
    if (!(p.host = malloc( native_size ))) { free( name ); return WSAENOBUFS; }
    status = unix_gethostbyname( &p );
    if (!status) status = ws32_result( p.host, TRUE, a->host, a->size, capacity );
    else if (status == ERROR_INSUFFICIENT_BUFFER) status = WSAENOBUFS;
    free( p.host ); free( name );
    return status;
}

static NTSTATUS wow64_unix_gethostname( void *args )
{
    const struct ws32_hn *a = args;
    struct gethostname_params p;
    NTSTATUS status;
    if (!a->size) return WSAEFAULT;
    if (a->size > WS32_BUFFER_LIMIT) return WSAENOBUFS;
    if (!(p.name = calloc( 1, a->size ))) return WSAENOBUFS;
    p.size = a->size;
    status = unix_gethostname( &p );
    if (!status && !memchr( p.name, 0, a->size )) status = WSAEFAULT;
    if (!status) status = ws32_publish( a->name, p.name, strlen( p.name ) + 1, 0, NULL, 0 );
    free( p.name );
    return status;
}

static NTSTATUS wow64_unix_getnameinfo( void *args )
{
    const struct ws32_ni *a = args;
    struct WS_sockaddr_storage address;
    struct getnameinfo_params p = {0};
    NTSTATUS status;
    if (a->addr_len < sizeof(struct WS_sockaddr) || a->addr_len > sizeof(address)) return WSAEFAULT;
    if (a->host_len > WS32_BUFFER_LIMIT || a->serv_len > WS32_BUFFER_LIMIT) return WSAENOBUFS;
    if ((status = ws32_read( &address, a->addr, a->addr_len ))) return status;
    p.addr = (const struct WS_sockaddr *)&address; p.addr_len = a->addr_len; p.flags = a->flags;
    p.host_len = a->host_len; p.serv_len = a->serv_len;
    if (a->host_len && (!a->host || !(p.host = calloc( 1, a->host_len )))) return a->host ? WSAENOBUFS : WSAEFAULT;
    if (a->serv_len && (!a->serv || !(p.serv = calloc( 1, a->serv_len ))))
    { free( p.host ); return a->serv ? WSAENOBUFS : WSAEFAULT; }
    status = unix_getnameinfo( &p );
    if (!status && ((p.host && !memchr( p.host, 0, p.host_len )) ||
                    (p.serv && !memchr( p.serv, 0, p.serv_len )))) status = WSAEFAULT;
    if (!status) status = ws32_publish( a->host, p.host, p.host ? strlen( p.host ) + 1 : 0,
                                       a->serv, p.serv, p.serv ? strlen( p.serv ) + 1 : 0 );
    free( p.host ); free( p.serv );
    return status;
}
#else
static NTSTATUS wow64_unix_getaddrinfo( void *args )
{
    struct
    {
        PTR32 node;
        PTR32 service;
        PTR32 hints;
        PTR32 info;
        PTR32 size;
    } const *params32 = args;

    NTSTATUS status;
    struct WS_addrinfo hints;
    struct getaddrinfo_params params =
    {
        ULongToPtr( params32->node ),
        ULongToPtr( params32->service ),
        NULL,
        NULL,
        ULongToPtr(params32->size)
    };

    if (params32->hints)
    {
        const struct WS_addrinfo32 *hints32 = ULongToPtr(params32->hints);
        hints.ai_flags    = hints32->ai_flags;
        hints.ai_family   = hints32->ai_family;
        hints.ai_socktype = hints32->ai_socktype;
        hints.ai_protocol = hints32->ai_protocol;
        params.hints = &hints;
    }

    if (!(params.info = malloc( *params.size ))) return WSAENOBUFS;
    status = unix_getaddrinfo( &params );
    if (!status) put_addrinfo32( params.info, ULongToPtr(params32->info), ULongToPtr(params32->size), params32->info );
    free( params.info );
    return status;
}


static NTSTATUS wow64_unix_gethostbyaddr( void *args )
{
    struct
    {
        PTR32 addr;
        int   len;
        int   family;
        PTR32 host;
        PTR32 size;
    } const *params32 = args;

    NTSTATUS status;
    struct gethostbyaddr_params params =
    {
        ULongToPtr( params32->addr ),
        params32->len,
        params32->family,
        NULL,
        ULongToPtr(params32->size)
    };

    if (!(params.host = malloc( *params.size ))) return WSAENOBUFS;
    status = unix_gethostbyaddr( &params );
    if (!status)
        status = put_hostent32( params.host, ULongToPtr(params32->host), ULongToPtr(params32->size), params32->host );
    free( params.host );
    return status;
}


static NTSTATUS wow64_unix_gethostbyname( void *args )
{
    struct
    {
        PTR32 name;
        PTR32 host;
        PTR32 size;
    } const *params32 = args;

    NTSTATUS status;
    struct gethostbyname_params params =
    {
        ULongToPtr( params32->name ),
        NULL,
        ULongToPtr(params32->size)
    };

    if (!(params.host = malloc( *params.size ))) return WSAENOBUFS;
    status = unix_gethostbyname( &params );
    if (!status)
        status = put_hostent32( params.host, ULongToPtr(params32->host), ULongToPtr(params32->size), params32->host );
    free( params.host );
    return status;
}


static NTSTATUS wow64_unix_gethostname( void *args )
{
    struct
    {
        PTR32 name;
        unsigned int size;
    } const *params32 = args;

    struct gethostname_params params = { ULongToPtr(params32->name), params32->size };

    if (!unix_gethostname( &params )) return 0;
    return errno_from_unix( errno );
}


static NTSTATUS wow64_unix_getnameinfo( void *args )
{
    struct
    {
        PTR32 addr;
        int addr_len;
        PTR32 host;
        DWORD host_len;
        PTR32 serv;
        DWORD serv_len;
        unsigned int flags;
    } const *params32 = args;

    struct getnameinfo_params params =
    {
        ULongToPtr( params32->addr ),
        params32->addr_len,
        ULongToPtr( params32->host ),
        params32->host_len,
        ULongToPtr( params32->serv ),
        params32->serv_len,
        params32->flags
    };

    return unix_getnameinfo( &params );
}

#endif

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    wow64_unix_getaddrinfo,
    wow64_unix_gethostbyaddr,
    wow64_unix_gethostbyname,
    wow64_unix_gethostname,
    wow64_unix_getnameinfo,
};

#if defined(__APPLE__) && defined(__aarch64__)
static const struct wine_unixlib_dispatch_entry_v2 ws32_entries[] =
{
    WINE_UNIXLIB_DISPATCH_ARGS_V2( struct ws32_gai, WINE_UNIXLIB_DISPATCH_ENTRY_NESTED | WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT ),
    WINE_UNIXLIB_DISPATCH_ARGS_V2( struct ws32_hba, WINE_UNIXLIB_DISPATCH_ENTRY_NESTED | WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT ),
    WINE_UNIXLIB_DISPATCH_ARGS_V2( struct ws32_hbn, WINE_UNIXLIB_DISPATCH_ENTRY_NESTED | WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT ),
    WINE_UNIXLIB_DISPATCH_ARGS_V2( struct ws32_hn, WINE_UNIXLIB_DISPATCH_ENTRY_NESTED | WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT ),
    WINE_UNIXLIB_DISPATCH_ARGS_V2( struct ws32_ni, WINE_UNIXLIB_DISPATCH_ENTRY_NESTED | WINE_UNIXLIB_DISPATCH_ENTRY_HAS_OUTPUT ),
};
WINE_UNIXLIB_DISPATCH_SOURCE_V2( __wine_unix_call_wow64_funcs, ws32_entries );
C_ASSERT( ARRAYSIZE(ws32_entries) == ws_unix_funcs_count );
#endif

C_ASSERT( ARRAYSIZE(__wine_unix_call_wow64_funcs) == ws_unix_funcs_count );

#endif  /* _WIN64 */
