/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/tcpip.h>
#include <ipxe/if_ether.h>
#include <ipxe/crc32.h>
#include <ipxe/fragment.h>
#include <ipxe/ipstat.h>
#include <ipxe/ndp.h>
#include <ipxe/ipv6.h>

/** @file
 *
 * IPv6 protocol
 *
 */

/* Disambiguate the various error causes */
#define EINVAL_LEN __einfo_error ( EINFO_EINVAL_LEN )
#define EINFO_EINVAL_LEN \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Invalid length" )
#define ENOTSUP_VER __einfo_error ( EINFO_ENOTSUP_VER )
#define EINFO_ENOTSUP_VER \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01, "Unsupported version" )
#define ENOTSUP_HDR __einfo_error ( EINFO_ENOTSUP_HDR )
#define EINFO_ENOTSUP_HDR \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x02, "Unsupported header type" )
#define ENOTSUP_OPT __einfo_error ( EINFO_ENOTSUP_OPT )
#define EINFO_ENOTSUP_OPT \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x03, "Unsupported option" )

/** List of IPv6 miniroutes */
struct list_head ipv6_miniroutes = LIST_HEAD_INIT ( ipv6_miniroutes );

/** IPv6 statistics */
static struct ip_statistics ipv6_stats;

/** IPv6 statistics family */
struct ip_statistics_family
ipv6_statistics_family __ip_statistics_family ( IP_STATISTICS_IPV6 ) = {
	.version = 6,
	.stats = &ipv6_stats,
};

/** Entry in the ipv6 policy table */
struct ipv6_policytable_entry {
	struct in6_addr address;
	unsigned int prefix_len;
	struct in6_addr prefix_mask;
	unsigned int precedence;
	unsigned int label;
};

/** IPv6 policy table according to RFC 6724
 *
 * Prefix        Precedence Label
 * ::1/128               50     0
 * ::/0                  40     1
 * ::ffff:0:0/96         35     4
 * 2002::/16             30     2
 * 2001::/32              5     5
 * fc00::/7               3    13
 * ::/96                  1     3
 * fec0::/10              1    11
 * 3ffe::/16              1    12
 *
 * The label is used for source address selection.
 * The precedence and label are used for destination
 * address selection (not implemented here).
 */
static const struct ipv6_policytable_entry policytable[] = {
	{
	  .address = { .s6_addr16 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, htons( 0x0001 ) } },
	  .prefix_len = 128,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff } },
	  .precedence = 50,
	  .label = 0
	},
	{
	  .address = { .s6_addr16 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 0,
	  .prefix_mask = { .s6_addr16 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 40,
	  .label = 1
	},
	{
	  .address = { .s6_addr16 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0xffff, 0x0, 0x0 } },
	  .prefix_len = 96,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0, 0x0 } },
	  .precedence = 35,
	  .label = 4
	},
	{
	  .address = { .s6_addr16 = { htons( 0x2002 ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 16,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 30,
	  .label = 2
	},
	{
	  .address = { .s6_addr16 = { htons( 0x2001 ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 32,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0xffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 5,
	  .label = 5
	},
	{
	  .address = { .s6_addr16 = { htons( 0xfc00 ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 7,
	  .prefix_mask = { .s6_addr16 = { htons( 0xfe00 ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 3,
	  .label = 13
	},
	{
	  .address = { .s6_addr16 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 96,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0, 0x0 } },
	  .precedence = 1,
	  .label = 3
	},
	{
	  .address = { .s6_addr16 = { htons( 0xfec0 ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 10,
	  .prefix_mask = { .s6_addr16 = { 0xffc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 1,
	  .label = 11
	},
	{
	  .address = { .s6_addr16 = { htons( 0x3ffe ), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .prefix_len = 16,
	  .prefix_mask = { .s6_addr16 = { 0xffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } },
	  .precedence = 1,
	  .label = 12
	}
};

/**
 * Determine debugging colour for IPv6 debug messages
 *
 * @v in		IPv6 address
 * @ret col		Debugging colour (for DBGC())
 */
static uint32_t ipv6col ( struct in6_addr *in ) {
	return crc32_le ( 0, in, sizeof ( *in ) );
}

/**
 * Dump IPv6 routing table entry
 *
 * @v miniroute		Routing table entry
 */
static inline __attribute__ (( always_inline )) void
ipv6_dump_miniroute ( struct ipv6_miniroute *miniroute ) {
	struct net_device *netdev = miniroute->netdev;

	DBGC ( netdev, "IPv6 %s has %s %s/%d", netdev->name,
	       ( ( miniroute->flags & IPV6_HAS_ADDRESS ) ?
		 "address" : "prefix" ),
	       inet6_ntoa ( &miniroute->address ), miniroute->prefix_len );
	if ( miniroute->flags & IPV6_HAS_ROUTER )
		DBGC ( netdev, " router %s", inet6_ntoa ( &miniroute->router ));
	DBGC ( netdev, "\n" );
}

/**
 * Check if network device has a specific IPv6 address
 *
 * @v netdev		Network device
 * @v addr		IPv6 address
 * @ret has_addr	Network device has this IPv6 address
 */
int ipv6_has_addr ( struct net_device *netdev, struct in6_addr *addr ) {
	struct ipv6_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv6_miniroutes, list ) {
		if ( ( miniroute->netdev == netdev ) &&
		     ( miniroute->flags & IPV6_HAS_ADDRESS ) &&
		     ( memcmp ( &miniroute->address, addr,
				sizeof ( miniroute->address ) ) == 0 ) ) {
			/* Found matching address */
			return 1;
		}
	}
	return 0;
}

/**
 * Check if IPv6 address is within a routing table entry's local network
 *
 * @v miniroute		Routing table entry
 * @v address		IPv6 address
 * @ret is_on_link	Address is within this entry's local network
 */
static int ipv6_is_on_link ( struct ipv6_miniroute *miniroute,
			     struct in6_addr *address ) {
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( address->s6_addr32 ) /
			    sizeof ( address->s6_addr32[0] ) ) ; i++ ) {
		if ( (( address->s6_addr32[i] ^ miniroute->address.s6_addr32[i])
		      & miniroute->prefix_mask.s6_addr32[i] ) != 0 )
			return 0;
	}
	return 1;
}

/**
 * Find IPv6 routing table entry for a given address
 *
 * @v netdev		Network device
 * @v address		IPv6 address
 * @ret miniroute	Routing table entry, or NULL if not found
 */
static struct ipv6_miniroute * ipv6_miniroute ( struct net_device *netdev,
						struct in6_addr *address ) {
	struct ipv6_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv6_miniroutes, list ) {
		if ( ( miniroute->netdev == netdev ) &&
		     ipv6_is_on_link ( miniroute, address ) ) {
			return miniroute;
		}
	}
	return NULL;
}

/**
 * Add IPv6 routing table entry
 *
 * @v netdev		Network device
 * @v address		IPv6 address (or prefix)
 * @v prefix_len	Prefix length
 * @v flags		Flags
 * @ret miniroute	Routing table entry, or NULL on failure
 */
static struct ipv6_miniroute * ipv6_add_miniroute ( struct net_device *netdev,
						    struct in6_addr *address,
						    unsigned int prefix_len,
						    unsigned int flags ) {
	struct ipv6_miniroute *miniroute;
	uint8_t *prefix_mask;

	/* Create routing table entry */
	miniroute = zalloc ( sizeof ( *miniroute ) );
	if ( ! miniroute )
		return NULL;
	miniroute->netdev = netdev_get ( netdev );
	memcpy ( &miniroute->address, address, sizeof ( miniroute->address ) );
	miniroute->prefix_len = prefix_len;
	assert ( prefix_len <= ( 8 * sizeof ( miniroute->prefix_mask ) ) );
	for ( prefix_mask = miniroute->prefix_mask.s6_addr ; prefix_len >= 8 ;
	      prefix_mask++, prefix_len -= 8 ) {
		*prefix_mask = 0xff;
	}
	if ( prefix_len )
		*prefix_mask <<= ( 8 - prefix_len );
	miniroute->flags = flags;
	list_add ( &miniroute->list, &ipv6_miniroutes );
	ipv6_dump_miniroute ( miniroute );

	return miniroute;
}

/**
 * Define IPv6 on-link prefix
 *
 * @v netdev		Network device
 * @v prefix		IPv6 address prefix
 * @v prefix_len	Prefix length
 * @v router		Router address (or NULL)
 * @ret rc		Return status code
 */
int ipv6_set_prefix ( struct net_device *netdev, struct in6_addr *prefix,
		      unsigned int prefix_len, struct in6_addr *router ) {
	struct ipv6_miniroute *miniroute;
	int changed;

	/* Find or create routing table entry */
	miniroute = ipv6_miniroute ( netdev, prefix );
	if ( ! miniroute )
		miniroute = ipv6_add_miniroute ( netdev, prefix, prefix_len, 0);
	if ( ! miniroute )
		return -ENOMEM;

	/* Record router and add to start or end of list as appropriate */
	list_del ( &miniroute->list );
	if ( router ) {
		changed = ( ( ! ( miniroute->flags & IPV6_HAS_ROUTER ) ) ||
			    ( memcmp ( &miniroute->router, router,
				       sizeof ( miniroute->router ) ) != 0 ) );
		miniroute->flags |= IPV6_HAS_ROUTER;
		memcpy ( &miniroute->router, router,
			 sizeof ( miniroute->router ) );
		list_add_tail ( &miniroute->list, &ipv6_miniroutes );
	} else {
		changed = ( miniroute->flags & IPV6_HAS_ROUTER );
		miniroute->flags &= ~IPV6_HAS_ROUTER;
		list_add ( &miniroute->list, &ipv6_miniroutes );
	}
	if ( changed )
		ipv6_dump_miniroute ( miniroute );

	return 0;
}

/**
 * Add IPv6 on-link address
 *
 * @v netdev		Network device
 * @v address		IPv6 address
 * @ret rc		Return status code
 *
 * An on-link prefix for the address must already exist.
 */
int ipv6_set_address ( struct net_device *netdev, struct in6_addr *address ) {
	struct ipv6_miniroute *miniroute;
	int changed;

	/* Find routing table entry */
	miniroute = ipv6_miniroute ( netdev, address );
	if ( ! miniroute )
		return -EADDRNOTAVAIL;

	/* Record address */
	changed = ( ( ! ( miniroute->flags & IPV6_HAS_ADDRESS ) ) ||
		    ( memcmp ( &miniroute->address, address,
			       sizeof ( miniroute->address ) ) != 0 ) );
	memcpy ( &miniroute->address, address, sizeof ( miniroute->address ) );
	miniroute->flags |= IPV6_HAS_ADDRESS;
	if ( changed )
		ipv6_dump_miniroute ( miniroute );

	return 0;
}

/**
 * Return the policy table entry for the specified address
 *
 * @v address		IPv6 address
 * @ret rc		Policy table entry
 *
 * With the default policy table, this function never returns NULL.
 */
static const struct ipv6_policytable_entry* ipv6_policytable_get(struct in6_addr *address) {
	unsigned int i, j;
	const struct ipv6_policytable_entry* best = NULL;
	int skip;

	for ( i = 0; i < sizeof( policytable ) / sizeof( policytable[0] ); ++i ) {
		skip = 0;
		for ( j = 0; j < ( sizeof ( address->s6_addr32 ) / sizeof ( address->s6_addr32[0] ) ) ; ++j ) {
			if ( (( address->s6_addr32[j] ^ policytable[i].address.s6_addr32[j])
			  & policytable[i].prefix_mask.s6_addr32[j] ) != 0 )
			{
				skip = 1;
				break;
			}
		}
		if ( !skip && ( best == NULL || policytable[i].prefix_len > best->prefix_len ) )
			best = &policytable[i];
	}
	return best;
}

/**
 * Source address selection rule 1
 *
 * @v first		First IPv6 address
 * @v second		First IPv6 address
 * @v dest		Destination address
 * @ret rc		Comparison result
 *
 * This function implements the first rule from RFC 6724, section 5. It tests whether
 * either of the addresses is equal to the destination address.
 *
 * If the first address should be preferred over the second, this function returns -1.
 * If the second address should be preferred over the first, this function returns 1.
 * If neither the first nor the second address should be preferred over the other, this
 * function returns 0.
 */
static int address_selection_compare_identical(struct ipv6_miniroute *first, struct ipv6_miniroute *second, struct in6_addr *dest)
{
	int firstIdentical = IN6_ARE_ADDR_EQUAL( first, dest ),
	  secondIdentical = IN6_ARE_ADDR_EQUAL( second, dest );

	if (firstIdentical && !secondIdentical)
		return -1;
	else if (!firstIdentical && secondIdentical)
		return 1;
	else
		return 0;
}

/**
 * Source address selection rule 2
 *
 * @v first		First IPv6 address
 * @v second		First IPv6 address
 * @v dest		Destination address
 * @ret rc		Comparison result
 *
 * This function implements the second rule from RFC 6724, section 5. It determines
 * the preferred address by comparing the scope of the first and second address and
 * the destination.
 *
 * We only consider the link-local and global scopes, since all other scopes are
 * irrelevant for iPXE.
 *
 * If the first address should be preferred over the second, this function returns -1.
 * If the second address should be preferred over the first, this function returns 1.
 * If neither the first nor the second address should be preferred over the other, this
 * function returns 0.
 */
static int address_selection_compare_scope(struct ipv6_miniroute *first, struct ipv6_miniroute *second, struct in6_addr *dest)
{
	int firstLinkLocal = IN6_IS_ADDR_NONGLOBAL( &first->address ),
	  secondLinkLocal = IN6_IS_ADDR_NONGLOBAL( &second->address ),
	  destLinkLocal = IN6_IS_ADDR_NONGLOBAL( dest );

	if ( firstLinkLocal && !secondLinkLocal )
		return destLinkLocal ? -1 : 1;
	else if ( secondLinkLocal && !firstLinkLocal )
		return destLinkLocal ? 1 : -1;
	else
		return 0;
}

/**
 * Source address selection rule 6
 *
 * @v first		First IPv6 address
 * @v second		First IPv6 address
 * @v dest		Destination address
 * @ret rc		Comparison result
 *
 * This function implements the 6th rule from RFC 6724, section 5. It determines
 * the preferred address by comparing the policy label of the first and second address
 * with the destination's policy label.
 *
 * If the first address should be preferred over the second, this function returns -1.
 * If the second address should be preferred over the first, this function returns 1.
 * If neither the first nor the second address should be preferred over the other, this
 * function returns 0.
 */
static int address_selection_compare_label(struct ipv6_miniroute *first, struct ipv6_miniroute *second, struct in6_addr *dest) {
	unsigned int labelFirst = ipv6_policytable_get(&first->address)->label,
	  labelSecond = ipv6_policytable_get(&second->address)->label,
	  labelDest = ipv6_policytable_get(dest)->label;

	if ( labelFirst == labelDest && labelSecond != labelDest )
		return -1;
	else if ( labelFirst != labelDest && labelSecond == labelDest )
		return 1;
	else
		return 0;
}

/**
 * Returns the common prefix length of two ipv6 addresses
 *
 * @v first		First IPv6 address
 * @v second		First IPv6 address
 */
static unsigned int common_prefix_length(struct in6_addr *first, struct in6_addr *second) {
	uint64_t common_prefix = ( ( ( (uint64_t)htonl( first->s6_addr32[0] ) ) << 32 ) | (uint64_t)htonl( first->s6_addr32[1] ) ) ^
	  ( ( ( (uint64_t)htonl( second->s6_addr32[0] ) ) << 32 ) | (uint64_t)htonl( second->s6_addr32[1] ) );

	unsigned int len = 0;
	while ( common_prefix >> len != 0 )
		++len;

	return 64 - len;
}

/**
 * Source address selection rule 8
 *
 * @v first		First IPv6 address
 * @v second		First IPv6 address
 * @v dest		Destination address
 * @ret rc		Comparison result
 *
 * This function implements the 8th rule from RFC 6724, section 5. It determines
 * the preferred address by choosing the address that shares the longest common
 * prefix with the destination.
 *
 * If the first address should be preferred over the second, this function returns -1.
 * If the second address should be preferred over the first, this function returns 1.
 * If neither the first nor the second address should be preferred over the other, this
 * function returns 0.
 */
static int address_selection_compare_common_prefix_length(struct ipv6_miniroute *first, struct ipv6_miniroute *second, struct in6_addr *dest) {
	unsigned int first_common_prefix_length = common_prefix_length(&first->address, dest),
	  second_common_prefix_length = common_prefix_length(&second->address, dest);

	if ( first_common_prefix_length > second_common_prefix_length )
		return -1;
	else if ( second_common_prefix_length > first_common_prefix_length )
		return 1;
	else
		return 0;
}

/**
 * Source address selection rules
 */
static int (*const source_address_comparison_functions[])(struct ipv6_miniroute*, struct ipv6_miniroute*, struct in6_addr*) = {
	&address_selection_compare_identical,
	&address_selection_compare_scope,
	&address_selection_compare_label,
	&address_selection_compare_common_prefix_length
};

/**
 * Perform IPv6 routing
 *
 * @v scope_id		Destination address scope ID (for link-local addresses)
 * @v dest		Final destination address
 * @ret dest		Next hop destination address
 * @ret miniroute	Routing table entry to use, or NULL if no route
 */
static struct ipv6_miniroute * ipv6_route ( unsigned int scope_id,
					    struct in6_addr **dest ) {
	struct ipv6_miniroute *current;
	struct ipv6_miniroute *best = NULL;
	unsigned int i;
	int cmp;

	/* Find route and source address */
	list_for_each_entry ( current, &ipv6_miniroutes, list ) {
		/* Skip closed network devices */
		if ( ! netdev_is_open ( current->netdev ) )
			continue;

		/* Skip routing table entries with no usable source address */
		if ( ! ( current->flags & IPV6_HAS_ADDRESS ) )
			continue;

		/* Skip all unusable addresses */
		if ( ( ! IN6_IS_ADDR_NONGLOBAL ( *dest ) || current->netdev->index != scope_id ) &&
		  ( IN6_IS_ADDR_NONGLOBAL ( *dest ) || ( ! ipv6_is_on_link ( current, *dest ) && ! ( current->flags & IPV6_HAS_ROUTER ) ) ) )
			continue;

		if ( best == NULL )
		{
			/* There is no previous best address, use the current one */
			best = current;
		}
		else
		{
			/* Compare this address to the previous best
			 *
			 * If the current address is strictly better than the previous best, use it.
			 * Otherwise, keep the previous best address.
			 */
			for ( i = 0; i < sizeof(source_address_comparison_functions) / sizeof(source_address_comparison_functions[0]); ++i )
			{
				cmp = source_address_comparison_functions[i]( best, current, *dest );
				if ( cmp < 0 )
				{
					/* The previous best address is strictly better than the current one in this comparison. */
					break;
				}
				else if ( cmp > 0 )
				{
					/*
					 * The current address is strictly beter than the previous best in this comparison. Use the current
					 * address as new best address.
					 */
					best = current;
					break;
				}
			}
		}
	}

	if ( best != NULL )
	{
		/* We found an address. Check if we need to use a router. */
		if ( best->flags & IPV6_HAS_ROUTER &&
		  ! ( IN6_IS_ADDR_NONGLOBAL ( *dest ) || ipv6_is_on_link ( best, *dest ) ) )
			*dest = &best->router;
	}

	return best;
}

/**
 * Determine transmitting network device
 *
 * @v st_dest		Destination network-layer address
 * @ret netdev		Transmitting network device, or NULL
 */
static struct net_device * ipv6_netdev ( struct sockaddr_tcpip *st_dest ) {
	struct sockaddr_in6 *sin6_dest = ( ( struct sockaddr_in6 * ) st_dest );
	struct in6_addr *dest = &sin6_dest->sin6_addr;
	struct ipv6_miniroute *miniroute;

	/* Find routing table entry */
	miniroute = ipv6_route ( sin6_dest->sin6_scope_id, &dest );
	if ( ! miniroute )
		return NULL;

	return miniroute->netdev;
}

/**
 * Check that received options can be safely ignored
 *
 * @v iphdr		IPv6 header
 * @v options		Options extension header
 * @v len		Maximum length of header
 * @ret rc		Return status code
 */
static int ipv6_check_options ( struct ipv6_header *iphdr,
				struct ipv6_options_header *options,
				size_t len ) {
	struct ipv6_option *option = options->options;
	struct ipv6_option *end = ( ( ( void * ) options ) + len );

	while ( option < end ) {
		if ( ! IPV6_CAN_IGNORE_OPT ( option->type ) ) {
			DBGC ( ipv6col ( &iphdr->src ), "IPv6 unrecognised "
			       "option type %#02x:\n", option->type );
			DBGC_HDA ( ipv6col ( &iphdr->src ), 0,
				   options, len );
			return -ENOTSUP_OPT;
		}
		if ( option->type == IPV6_OPT_PAD1 ) {
			option = ( ( ( void * ) option ) + 1 );
		} else {
			option = ( ( ( void * ) option->value ) + option->len );
		}
	}
	return 0;
}

/**
 * Check if fragment matches fragment reassembly buffer
 *
 * @v fragment		Fragment reassembly buffer
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret is_fragment	Fragment matches this reassembly buffer
 */
static int ipv6_is_fragment ( struct fragment *fragment,
			      struct io_buffer *iobuf, size_t hdrlen ) {
	struct ipv6_header *frag_iphdr = fragment->iobuf->data;
	struct ipv6_fragment_header *frag_fhdr =
		( fragment->iobuf->data + fragment->hdrlen -
		  sizeof ( *frag_fhdr ) );
	struct ipv6_header *iphdr = iobuf->data;
	struct ipv6_fragment_header *fhdr =
		( iobuf->data + hdrlen - sizeof ( *fhdr ) );

	return ( ( memcmp ( &iphdr->src, &frag_iphdr->src,
			    sizeof ( iphdr->src ) ) == 0 ) &&
		 ( fhdr->ident == frag_fhdr->ident ) );
}

/**
 * Get fragment offset
 *
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret offset		Offset
 */
static size_t ipv6_fragment_offset ( struct io_buffer *iobuf, size_t hdrlen ) {
	struct ipv6_fragment_header *fhdr =
		( iobuf->data + hdrlen - sizeof ( *fhdr ) );

	return ( ntohs ( fhdr->offset_more ) & IPV6_MASK_OFFSET );
}

/**
 * Check if more fragments exist
 *
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret more_frags	More fragments exist
 */
static int ipv6_more_fragments ( struct io_buffer *iobuf, size_t hdrlen ) {
	struct ipv6_fragment_header *fhdr =
		( iobuf->data + hdrlen - sizeof ( *fhdr ) );

	return ( fhdr->offset_more & htons ( IPV6_MASK_MOREFRAGS ) );
}

/** Fragment reassembler */
static struct fragment_reassembler ipv6_reassembler = {
	.list = LIST_HEAD_INIT ( ipv6_reassembler.list ),
	.is_fragment = ipv6_is_fragment,
	.fragment_offset = ipv6_fragment_offset,
	.more_fragments = ipv6_more_fragments,
	.stats = &ipv6_stats,
};

/**
 * Calculate IPv6 pseudo-header checksum
 *
 * @v iphdr		IPv6 header
 * @v len		Payload length
 * @v next_header	Next header type
 * @v csum		Existing checksum
 * @ret csum		Updated checksum
 */
static uint16_t ipv6_pshdr_chksum ( struct ipv6_header *iphdr, size_t len,
				    int next_header, uint16_t csum ) {
	struct ipv6_pseudo_header pshdr;

	/* Build pseudo-header */
	memcpy ( &pshdr.src, &iphdr->src, sizeof ( pshdr.src ) );
	memcpy ( &pshdr.dest, &iphdr->dest, sizeof ( pshdr.dest ) );
	pshdr.len = htonl ( len );
	memset ( pshdr.zero, 0, sizeof ( pshdr.zero ) );
	pshdr.next_header = next_header;

	/* Update the checksum value */
	return tcpip_continue_chksum ( csum, &pshdr, sizeof ( pshdr ) );
}

/**
 * Transmit IPv6 packet
 *
 * @v iobuf		I/O buffer
 * @v tcpip		Transport-layer protocol
 * @v st_src		Source network-layer address
 * @v st_dest		Destination network-layer address
 * @v netdev		Network device to use if no route found, or NULL
 * @v trans_csum	Transport-layer checksum to complete, or NULL
 * @ret rc		Status
 *
 * This function expects a transport-layer segment and prepends the
 * IPv6 header
 */
static int ipv6_tx ( struct io_buffer *iobuf,
		     struct tcpip_protocol *tcpip_protocol,
		     struct sockaddr_tcpip *st_src,
		     struct sockaddr_tcpip *st_dest,
		     struct net_device *netdev,
		     uint16_t *trans_csum ) {
	struct sockaddr_in6 *sin6_src = ( ( struct sockaddr_in6 * ) st_src );
	struct sockaddr_in6 *sin6_dest = ( ( struct sockaddr_in6 * ) st_dest );
	struct ipv6_miniroute *miniroute;
	struct ipv6_header *iphdr;
	struct in6_addr *src = NULL;
	struct in6_addr *next_hop;
	uint8_t ll_dest_buf[MAX_LL_ADDR_LEN];
	const void *ll_dest;
	size_t len;
	int rc;

	/* Update statistics */
	ipv6_stats.out_requests++;

	/* Fill up the IPv6 header, except source address */
	len = iob_len ( iobuf );
	iphdr = iob_push ( iobuf, sizeof ( *iphdr ) );
	memset ( iphdr, 0, sizeof ( *iphdr ) );
	iphdr->ver_tc_label = htonl ( IPV6_VER );
	iphdr->len = htons ( len );
	iphdr->next_header = tcpip_protocol->tcpip_proto;
	iphdr->hop_limit = IPV6_HOP_LIMIT;
	memcpy ( &iphdr->dest, &sin6_dest->sin6_addr, sizeof ( iphdr->dest ) );

	/* Use routing table to identify next hop and transmitting netdev */
	next_hop = &iphdr->dest;
	if ( ( miniroute = ipv6_route ( sin6_dest->sin6_scope_id,
					&next_hop ) ) != NULL ) {
		src = &miniroute->address;
		netdev = miniroute->netdev;
	}
	if ( ! netdev ) {
		DBGC ( ipv6col ( &iphdr->dest ), "IPv6 has no route to %s\n",
		       inet6_ntoa ( &iphdr->dest ) );
		ipv6_stats.out_no_routes++;
		rc = -ENETUNREACH;
		goto err;
	}
	if ( sin6_src && ! IN6_IS_ADDR_UNSPECIFIED ( &sin6_src->sin6_addr ) )
		src = &sin6_src->sin6_addr;
	if ( src )
		memcpy ( &iphdr->src, src, sizeof ( iphdr->src ) );

	/* Fix up checksums */
	if ( trans_csum ) {
		*trans_csum = ipv6_pshdr_chksum ( iphdr, len,
						  tcpip_protocol->tcpip_proto,
						  *trans_csum );
		if ( ! *trans_csum )
			*trans_csum = tcpip_protocol->zero_csum;
	}

	/* Print IPv6 header for debugging */
	DBGC2 ( ipv6col ( &iphdr->dest ), "IPv6 TX %s->",
		inet6_ntoa ( &iphdr->src ) );
	DBGC2 ( ipv6col ( &iphdr->dest ), "%s len %zd next %d\n",
		inet6_ntoa ( &iphdr->dest ), len, iphdr->next_header );

	/* Calculate link-layer destination address, if possible */
	if ( IN6_IS_ADDR_MULTICAST ( next_hop ) ) {
		/* Multicast address */
		ipv6_stats.out_mcast_pkts++;
		if ( ( rc = netdev->ll_protocol->mc_hash ( AF_INET6, next_hop,
							   ll_dest_buf ) ) !=0){
			DBGC ( ipv6col ( &iphdr->dest ), "IPv6 could not hash "
			       "multicast %s: %s\n", inet6_ntoa ( next_hop ),
			       strerror ( rc ) );
			goto err;
		}
		ll_dest = ll_dest_buf;
	} else {
		/* Unicast address */
		ll_dest = NULL;
	}

	/* Update statistics */
	ipv6_stats.out_transmits++;
	ipv6_stats.out_octets += iob_len ( iobuf );

	/* Hand off to link layer (via NDP if applicable) */
	if ( ll_dest ) {
		if ( ( rc = net_tx ( iobuf, netdev, &ipv6_protocol, ll_dest,
				     netdev->ll_addr ) ) != 0 ) {
			DBGC ( ipv6col ( &iphdr->dest ), "IPv6 could not "
			       "transmit packet via %s: %s\n",
			       netdev->name, strerror ( rc ) );
			return rc;
		}
	} else {
		if ( ( rc = ndp_tx ( iobuf, netdev, next_hop, &iphdr->src,
				     netdev->ll_addr ) ) != 0 ) {
			DBGC ( ipv6col ( &iphdr->dest ), "IPv6 could not "
			       "transmit packet via %s: %s\n",
			       netdev->name, strerror ( rc ) );
			return rc;
		}
	}

	return 0;

 err:
	free_iob ( iobuf );
	return rc;
}

/**
 * Process incoming IPv6 packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer destination source
 * @v flags		Packet flags
 * @ret rc		Return status code
 *
 * This function expects an IPv6 network datagram. It processes the
 * headers and sends it to the transport layer.
 */
static int ipv6_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		     const void *ll_dest __unused,
		     const void *ll_source __unused,
		     unsigned int flags __unused ) {
	struct ipv6_header *iphdr = iobuf->data;
	union ipv6_extension_header *ext;
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr_tcpip st;
	} src, dest;
	uint16_t pshdr_csum;
	size_t len;
	size_t hdrlen;
	size_t extlen;
	int this_header;
	int next_header;
	int rc;

	/* Update statistics */
	ipv6_stats.in_receives++;
	ipv6_stats.in_octets += iob_len ( iobuf );
	if ( flags & LL_BROADCAST ) {
		ipv6_stats.in_bcast_pkts++;
	} else if ( flags & LL_MULTICAST ) {
		ipv6_stats.in_mcast_pkts++;
	}

	/* Sanity check the IPv6 header */
	if ( iob_len ( iobuf ) < sizeof ( *iphdr ) ) {
		DBGC ( ipv6col ( &iphdr->src ), "IPv6 packet too short at %zd "
		       "bytes (min %zd bytes)\n", iob_len ( iobuf ),
		       sizeof ( *iphdr ) );
		rc = -EINVAL_LEN;
		goto err_header;
	}
	if ( ( iphdr->ver_tc_label & htonl ( IPV6_MASK_VER ) ) !=
	     htonl ( IPV6_VER ) ) {
		DBGC ( ipv6col ( &iphdr->src ), "IPv6 version %#08x not "
		       "supported\n", ntohl ( iphdr->ver_tc_label ) );
		rc = -ENOTSUP_VER;
		goto err_header;
	}

	/* Truncate packet to specified length */
	len = ntohs ( iphdr->len );
	if ( len > iob_len ( iobuf ) ) {
		DBGC ( ipv6col ( &iphdr->src ), "IPv6 length too long at %zd "
		       "bytes (packet is %zd bytes)\n", len, iob_len ( iobuf ));
		ipv6_stats.in_truncated_pkts++;
		rc = -EINVAL_LEN;
		goto err_other;
	}
	iob_unput ( iobuf, ( iob_len ( iobuf ) - len - sizeof ( *iphdr ) ) );
	hdrlen = sizeof ( *iphdr );

	/* Print IPv6 header for debugging */
	DBGC2 ( ipv6col ( &iphdr->src ), "IPv6 RX %s<-",
		inet6_ntoa ( &iphdr->dest ) );
	DBGC2 ( ipv6col ( &iphdr->src ), "%s len %zd next %d\n",
		inet6_ntoa ( &iphdr->src ), len, iphdr->next_header );

	/* Discard unicast packets not destined for us */
	if ( ( ! ( flags & LL_MULTICAST ) ) &&
	     ( ! ipv6_has_addr ( netdev, &iphdr->dest ) ) ) {
		DBGC ( ipv6col ( &iphdr->src ), "IPv6 discarding non-local "
		       "unicast packet for %s\n", inet6_ntoa ( &iphdr->dest ) );
		ipv6_stats.in_addr_errors++;
		rc = -EPIPE;
		goto err_other;
	}

	/* Process any extension headers */
	next_header = iphdr->next_header;
	while ( 1 ) {

		/* Extract extension header */
		this_header = next_header;
		ext = ( iobuf->data + hdrlen );
		extlen = sizeof ( ext->pad );
		if ( iob_len ( iobuf ) < ( hdrlen + extlen ) ) {
			DBGC ( ipv6col ( &iphdr->src ), "IPv6 too short for "
			       "extension header type %d at %zd bytes (min "
			       "%zd bytes)\n", this_header,
			       ( iob_len ( iobuf ) - hdrlen ), extlen );
			rc = -EINVAL_LEN;
			goto err_header;
		}

		/* Determine size of extension header (if applicable) */
		if ( ( this_header == IPV6_HOPBYHOP ) ||
		     ( this_header == IPV6_DESTINATION ) ||
		     ( this_header == IPV6_ROUTING ) ) {
			/* Length field is present */
			extlen += ext->common.len;
		} else if ( this_header == IPV6_FRAGMENT ) {
			/* Length field is reserved and ignored (RFC2460) */
		} else {
			/* Not an extension header; assume rest is payload */
			break;
		}
		if ( iob_len ( iobuf ) < ( hdrlen + extlen ) ) {
			DBGC ( ipv6col ( &iphdr->src ), "IPv6 too short for "
			       "extension header type %d at %zd bytes (min "
			       "%zd bytes)\n", this_header,
			       ( iob_len ( iobuf ) - hdrlen ), extlen );
			rc = -EINVAL_LEN;
			goto err_header;
		}
		hdrlen += extlen;
		next_header = ext->common.next_header;
		DBGC2 ( ipv6col ( &iphdr->src ), "IPv6 RX %s<-",
			inet6_ntoa ( &iphdr->dest ) );
		DBGC2 ( ipv6col ( &iphdr->src ), "%s ext type %d len %zd next "
			"%d\n", inet6_ntoa ( &iphdr->src ), this_header,
			extlen, next_header );

		/* Process this extension header */
		if ( ( this_header == IPV6_HOPBYHOP ) ||
		     ( this_header == IPV6_DESTINATION ) ) {

			/* Check that all options can be ignored */
			if ( ( rc = ipv6_check_options ( iphdr, &ext->options,
							 extlen ) ) != 0 )
				goto err_header;

		} else if ( this_header == IPV6_FRAGMENT ) {

			/* Reassemble fragments */
			iobuf = fragment_reassemble ( &ipv6_reassembler, iobuf,
						      &hdrlen );
			if ( ! iobuf )
				return 0;
			iphdr = iobuf->data;
		}
	}

	/* Construct socket address, calculate pseudo-header checksum,
	 * and hand off to transport layer
	 */
	memset ( &src, 0, sizeof ( src ) );
	src.sin6.sin6_family = AF_INET6;
	memcpy ( &src.sin6.sin6_addr, &iphdr->src,
		 sizeof ( src.sin6.sin6_addr ) );
	src.sin6.sin6_scope_id = netdev->index;
	memset ( &dest, 0, sizeof ( dest ) );
	dest.sin6.sin6_family = AF_INET6;
	memcpy ( &dest.sin6.sin6_addr, &iphdr->dest,
		 sizeof ( dest.sin6.sin6_addr ) );
	dest.sin6.sin6_scope_id = netdev->index;
	iob_pull ( iobuf, hdrlen );
	pshdr_csum = ipv6_pshdr_chksum ( iphdr, iob_len ( iobuf ),
					 next_header, TCPIP_EMPTY_CSUM );
	if ( ( rc = tcpip_rx ( iobuf, netdev, next_header, &src.st, &dest.st,
			       pshdr_csum, &ipv6_stats ) ) != 0 ) {
		DBGC ( ipv6col ( &src.sin6.sin6_addr ), "IPv6 received packet "
				"rejected by stack: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;

 err_header:
	ipv6_stats.in_hdr_errors++;
 err_other:
	free_iob ( iobuf );
	return rc;
}

/**
 * Parse IPv6 address
 *
 * @v string		IPv6 address string
 * @ret in		IPv6 address to fill in
 * @ret rc		Return status code
 */
int inet6_aton ( const char *string, struct in6_addr *in ) {
	uint16_t *word = in->s6_addr16;
	uint16_t *end = ( word + ( sizeof ( in->s6_addr16 ) /
				   sizeof ( in->s6_addr16[0] ) ) );
	uint16_t *pad = NULL;
	const char *nptr = string;
	char *endptr;
	unsigned long value;
	size_t pad_len;
	size_t move_len;

	/* Parse string */
	while ( 1 ) {

		/* Parse current word */
		value = strtoul ( nptr, &endptr, 16 );
		if ( value > 0xffff ) {
			DBG ( "IPv6 invalid word value %#lx in \"%s\"\n",
			      value, string );
			return -EINVAL;
		}
		*(word++) = htons ( value );

		/* Parse separator */
		if ( ! *endptr )
			break;
		if ( *endptr != ':' ) {
			DBG ( "IPv6 invalid separator '%c' in \"%s\"\n",
			      *endptr, string );
			return -EINVAL;
		}
		if ( ( endptr == nptr ) && ( nptr != string ) ) {
			if ( pad ) {
				DBG ( "IPv6 invalid multiple \"::\" in "
				      "\"%s\"\n", string );
				return -EINVAL;
			}
			pad = word;
		}
		nptr = ( endptr + 1 );

		/* Check for overrun */
		if ( word == end ) {
			DBG ( "IPv6 too many words in \"%s\"\n", string );
			return -EINVAL;
		}
	}

	/* Insert padding if specified */
	if ( pad ) {
		move_len = ( ( ( void * ) word ) - ( ( void * ) pad ) );
		pad_len = ( ( ( void * ) end ) - ( ( void * ) word ) );
		memmove ( ( ( ( void * ) pad ) + pad_len ), pad, move_len );
		memset ( pad, 0, pad_len );
	} else if ( word != end ) {
		DBG ( "IPv6 underlength address \"%s\"\n", string );
		return -EINVAL;
	}

	return 0;
}

/**
 * Convert IPv6 address to standard notation
 *
 * @v in		IPv6 address
 * @ret string		IPv6 address string in canonical format
 *
 * RFC5952 defines the canonical format for IPv6 textual representation.
 */
char * inet6_ntoa ( const struct in6_addr *in ) {
	static char buf[41]; /* ":xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx" */
	char *out = buf;
	char *longest_start = NULL;
	char *start = NULL;
	int longest_len = 1;
	int len = 0;
	char *dest;
	unsigned int i;
	uint16_t value;

	/* Format address, keeping track of longest run of zeros */
	for ( i = 0 ; i < ( sizeof ( in->s6_addr16 ) /
			    sizeof ( in->s6_addr16[0] ) ) ; i++ ) {
		value = ntohs ( in->s6_addr16[i] );
		if ( value == 0 ) {
			if ( len++ == 0 )
				start = out;
			if ( len > longest_len ) {
				longest_start = start;
				longest_len = len;
			}
		} else {
			len = 0;
		}
		out += sprintf ( out, ":%x", value );
	}

	/* Abbreviate longest run of zeros, if applicable */
	if ( longest_start ) {
		dest = strcpy ( ( longest_start + 1 ),
				( longest_start + ( 2 * longest_len ) ) );
		if ( dest[0] == '\0' )
			dest[1] = '\0';
		dest[0] = ':';
	}
	return ( ( longest_start == buf ) ? buf : ( buf + 1 ) );
}

/**
 * Transcribe IPv6 address
 *
 * @v net_addr		IPv6 address
 * @ret string		IPv6 address in standard notation
 *
 */
static const char * ipv6_ntoa ( const void *net_addr ) {
	return inet6_ntoa ( net_addr );
}

/**
 * Transcribe IPv6 socket address
 *
 * @v sa		Socket address
 * @ret string		Socket address in standard notation
 */
static const char * ipv6_sock_ntoa ( struct sockaddr *sa ) {
	static char buf[ 39 /* "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx" */ +
			 1 /* "%" */ + NETDEV_NAME_LEN + 1 /* NUL */ ];
	struct sockaddr_in6 *sin6 = ( ( struct sockaddr_in6 * ) sa );
	struct in6_addr *in = &sin6->sin6_addr;
	struct net_device *netdev;
	const char *netdev_name;

	/* Identify network device, if applicable */
	if ( IN6_IS_ADDR_NONGLOBAL ( in ) ) {
		netdev = find_netdev_by_index ( sin6->sin6_scope_id );
		netdev_name = ( netdev ? netdev->name : "UNKNOWN" );
	} else {
		netdev_name = NULL;
	}

	/* Format socket address */
	snprintf ( buf, sizeof ( buf ), "%s%s%s", inet6_ntoa ( in ),
		   ( netdev_name ? "%" : "" ),
		   ( netdev_name ? netdev_name : "" ) );
	return buf;
}

/**
 * Parse IPv6 socket address
 *
 * @v string		Socket address string
 * @v sa		Socket address to fill in
 * @ret rc		Return status code
 */
static int ipv6_sock_aton ( const char *string, struct sockaddr *sa ) {
	struct sockaddr_in6 *sin6 = ( ( struct sockaddr_in6 * ) sa );
	struct in6_addr in;
	struct net_device *netdev;
	size_t len;
	char *tmp;
	char *in_string;
	char *netdev_string;
	int rc;

	/* Create modifiable copy of string */
	tmp = strdup ( string );
	if ( ! tmp ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	in_string = tmp;

	/* Strip surrounding "[...]", if present */
	len = strlen ( in_string );
	if ( ( in_string[0] == '[' ) && ( in_string[ len - 1 ] == ']' ) ) {
		in_string[ len - 1 ] = '\0';
		in_string++;
	}

	/* Split at network device name, if present */
	netdev_string = strchr ( in_string, '%' );
	if ( netdev_string )
		*(netdev_string++) = '\0';

	/* Parse IPv6 address portion */
	if ( ( rc = inet6_aton ( in_string, &in ) ) != 0 )
		goto err_inet6_aton;

	/* Parse scope ID, if applicable */
	if ( netdev_string ) {

		/* Parse explicit network device name, if present */
		netdev = find_netdev ( netdev_string );
		if ( ! netdev ) {
			rc = -ENODEV;
			goto err_find_netdev;
		}
		sin6->sin6_scope_id = netdev->index;

	} else if ( IN6_IS_ADDR_NONGLOBAL ( &in ) ) {

		/* If no network device is explicitly specified for a
		 * link-local or multicast address, default to using
		 * "netX" (if existent).
		 */
		netdev = last_opened_netdev();
		if ( netdev )
			sin6->sin6_scope_id = netdev->index;
	}

	/* Copy IPv6 address portion to socket address */
	memcpy ( &sin6->sin6_addr, &in, sizeof ( sin6->sin6_addr ) );

 err_find_netdev:
 err_inet6_aton:
	free ( tmp );
 err_alloc:
	return rc;
}

/** IPv6 protocol */
struct net_protocol ipv6_protocol __net_protocol = {
	.name = "IPv6",
	.net_proto = htons ( ETH_P_IPV6 ),
	.net_addr_len = sizeof ( struct in6_addr ),
	.rx = ipv6_rx,
	.ntoa = ipv6_ntoa,
};

/** IPv6 TCPIP net protocol */
struct tcpip_net_protocol ipv6_tcpip_protocol __tcpip_net_protocol = {
	.name = "IPv6",
	.sa_family = AF_INET6,
	.header_len = sizeof ( struct ipv6_header ),
	.net_protocol = &ipv6_protocol,
	.tx = ipv6_tx,
	.netdev = ipv6_netdev,
};

/** IPv6 socket address converter */
struct sockaddr_converter ipv6_sockaddr_converter __sockaddr_converter = {
	.family = AF_INET6,
	.ntoa = ipv6_sock_ntoa,
	.aton = ipv6_sock_aton,
};

/**
 * Parse IPv6 address setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
int parse_ipv6_setting ( const struct setting_type *type __unused,
			 const char *value, void *buf, size_t len ) {
	struct in6_addr ipv6;
	int rc;

	/* Parse IPv6 address */
	if ( ( rc = inet6_aton ( value, &ipv6 ) ) != 0 )
		return rc;

	/* Copy to buffer */
	if ( len > sizeof ( ipv6 ) )
		len = sizeof ( ipv6 );
	memcpy ( buf, &ipv6, len );

	return ( sizeof ( ipv6 ) );
}

/**
 * Format IPv6 address setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
int format_ipv6_setting ( const struct setting_type *type __unused,
			  const void *raw, size_t raw_len, char *buf,
			  size_t len ) {
	const struct in6_addr *ipv6 = raw;

	if ( raw_len < sizeof ( *ipv6 ) )
		return -EINVAL;
	return snprintf ( buf, len, "%s", inet6_ntoa ( ipv6 ) );
}

/**
 * Create IPv6 network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ipv6_probe ( struct net_device *netdev ) {
	struct ipv6_miniroute *miniroute;
	struct in6_addr address;
	int prefix_len;
	int rc;

	/* Construct link-local address from EUI-64 as per RFC 2464 */
	memset ( &address, 0, sizeof ( address ) );
	prefix_len = ipv6_link_local ( &address, netdev );
	if ( prefix_len < 0 ) {
		rc = prefix_len;
		DBGC ( netdev, "IPv6 %s could not construct link-local "
		       "address: %s\n", netdev->name, strerror ( rc ) );
		return rc;
	}

	/* Create link-local address for this network device */
	miniroute = ipv6_add_miniroute ( netdev, &address, prefix_len,
					 IPV6_HAS_ADDRESS );
	if ( ! miniroute )
		return -ENOMEM;

	return 0;
}

/**
 * Destroy IPv6 network device
 *
 * @v netdev		Network device
 */
static void ipv6_remove ( struct net_device *netdev ) {
	struct ipv6_miniroute *miniroute;
	struct ipv6_miniroute *tmp;

	/* Delete all miniroutes for this network device */
	list_for_each_entry_safe ( miniroute, tmp, &ipv6_miniroutes, list ) {
		if ( miniroute->netdev == netdev ) {
			netdev_put ( miniroute->netdev );
			list_del ( &miniroute->list );
			free ( miniroute );
		}
	}
}

/** IPv6 network device driver */
struct net_driver ipv6_driver __net_driver = {
	.name = "IPv6",
	.probe = ipv6_probe,
	.remove = ipv6_remove,
};

/* Drag in objects via ipv6_protocol */
REQUIRING_SYMBOL ( ipv6_protocol );

/* Drag in ICMPv6 */
REQUIRE_OBJECT ( icmpv6 );

/* Drag in NDP */
REQUIRE_OBJECT ( ndp );
