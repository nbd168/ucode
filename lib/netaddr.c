/*
Copyright 2015-2018 Jo-Philipp Wich <jo@mein.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * # Network Address
 *
 * The `netaddr` module provides functions and the `netaddr.range` object type
 * for parsing, validating and manipulating IP addresses, network prefixes and
 * MAC addresses.
 *
 * Address ranges are represented by `netaddr.range` instances which carry the
 * address, its family and a prefix size (CIDR notation). Instances are
 * created with the `new()`, `IPv4()`, `IPv6()` or `MAC()` functions:
 *
 *   ```javascript
 *   import * as netaddr from 'netaddr';
 *
 *   const addr = netaddr.new('10.24.0.1/24');
 *   const addr = netaddr.new('10.24.0.1/255.255.255.0');
 *   const addr = netaddr.new('10.24.0.1', '255.255.255.0');  // separate netmask
 *   const addr = netaddr.new('10.24.0.1/24', 16);            // override netmask
 *
 *   const addr6 = netaddr.new('fe80::221:63ff:fe75:aa17/64');
 *   const addr6 = netaddr.new('fe80::221:63ff:fe75:aa17/ffff:ffff:ffff:ffff::');
 *
 *   const mac = netaddr.new('00:11:22:cc:dd:ee');
 *   const mac = netaddr.MAC('C0:B6:F9:00:00:00/24');
 *   ```
 *
 * The `checkv4()`, `checkv6()` and `checkmac()` functions provide
 * non-throwing validation, returning the canonical string representation of
 * the given address or `null` if the argument is not a valid address of the
 * respective family:
 *
 *   ```javascript
 *   netaddr.checkv4('127.0.0.1');  // "127.0.0.1"
 *   netaddr.checkv6('::1');        // "::1"
 *   netaddr.checkmac('00:11:22:cc:dd:ee');  // "00:11:22:CC:DD:EE"
 *   netaddr.checkv4('nonsense');   // null
 *   ```
 *
 * @module netaddr
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <math.h>

#include <net/if.h>
#include <arpa/inet.h>

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#include "ucode/module.h"


#define AF_BITS(f) \
	((f) == AF_INET ? 32 : \
		((f) == AF_INET6 ? 128 : \
			((f) == AF_PACKET ? 48 : 0)))

#define AF_BYTES(f) \
	((f) == AF_INET ? 4 : \
		((f) == AF_INET6 ? 16 : \
			((f) == AF_PACKET ? 6 : 0)))

typedef struct {
	union {
		struct in_addr v4;
		struct in6_addr v6;
		uint8_t mac[6];
		uint8_t u8[16];
	} addr;
	uint32_t scope;
	uint16_t family;
	int16_t bits;
} range_t;

static const char *range_type = "netaddr.range";

/*
 * range parsing / formatting
 */

static bool
parse_mac(const char *mac, uint8_t *mac_addr)
{
	unsigned long int n;
	char *e, sep = 0;
	int i;

	for (i = 0; i < 6; i++) {
		if (i > 0) {
			if (sep == 0 && (mac[0] == ':' || mac[0] == '-'))
				sep = mac[0];

			if (sep == 0 || mac[0] != sep)
				return false;

			mac++;
		}

		n = strtoul(mac, &e, 16);

		if (n > 0xFF)
			return false;

		mac += (e - mac);
		mac_addr[i] = n;
	}

	if (mac[0] != 0)
		return false;

	return true;
}

static bool
parse_mask(int family, const char *mask, int16_t *bits)
{
	char *e;
	union {
		struct in_addr v4;
		struct in6_addr v6;
		uint8_t mac[6];
		uint8_t u8[16];
	} m;

	if (family == AF_INET && inet_pton(AF_INET, mask, &m.v4)) {
		for (*bits = 0, m.v4.s_addr = ntohl(m.v4.s_addr);
			 *bits < AF_BITS(AF_INET) && (m.v4.s_addr << *bits) & 0x80000000;
			 ++*bits);
	}
	else if ((family == AF_INET6 && inet_pton(AF_INET6, mask, &m.v6)) ||
	         (family == AF_PACKET && parse_mac(mask, m.mac))) {
		for (*bits = 0;
			 *bits < AF_BITS(family) && (m.u8[*bits / 8] << (*bits % 8)) & 128;
			 ++*bits);
	}
	else {
		*bits = strtoul(mask, &e, 10);

		if (e == mask || *e != 0 || *bits > AF_BITS(family))
			return false;
	}

	return true;
}

static bool
parse_range(const char *dest, range_t *pp)
{
	char *p, *s, buf[INET6_ADDRSTRLEN * 2 + 2];

	strncpy(buf, dest, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	p = strchr(buf, '/');

	if (p)
		*p++ = 0;

	s = strchr(buf, '%');

	if (s)
		*s++ = 0;

	if (inet_pton(AF_INET, buf, &pp->addr.v4))
		pp->family = AF_INET;
	else if (inet_pton(AF_INET6, buf, &pp->addr.v6))
		pp->family = AF_INET6;
	else if (parse_mac(buf, pp->addr.mac))
		pp->family = AF_PACKET;
	else
		return false;

	if (s) {
		if (pp->family != AF_INET6)
			return false;

		if (!(pp->addr.v6.s6_addr[0] == 0xFE &&
		      pp->addr.v6.s6_addr[1] >= 0x80 &&
		      pp->addr.v6.s6_addr[2] <= 0xBF))
			return false;

		pp->scope = if_nametoindex(s);

		if (pp->scope == 0)
			return false;
	}
	else {
		pp->scope = 0;
	}

	if (p) {
		if (!parse_mask(pp->family, p, &pp->bits))
			return false;
	}
	else {
		pp->bits = AF_BITS(pp->family);
	}

	return true;
}

static uc_value_t *
format_range(uc_vm_t *vm, range_t *p)
{
	uc_stringbuf_t *buf = ucv_stringbuf_new();
	char tmp[INET6_ADDRSTRLEN + IF_NAMESIZE + 1];

	if (p->family == AF_PACKET) {
		ucv_stringbuf_printf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		                     p->addr.mac[0],
		                     p->addr.mac[1],
		                     p->addr.mac[2],
		                     p->addr.mac[3],
		                     p->addr.mac[4],
		                     p->addr.mac[5]);

		if (p->scope != 0) {
			if (if_indextoname(p->scope, tmp) != NULL)
				ucv_stringbuf_printf(buf, "%%%s", tmp);
		}

		if (p->bits < AF_BITS(AF_PACKET))
			ucv_stringbuf_printf(buf, "/%d", p->bits);
	}
	else {
		size_t len;

		if (!inet_ntop(p->family, &p->addr.v6, tmp, sizeof(tmp)))
			goto err;

		len = strlen(tmp);

		if (p->scope != 0 && if_indextoname(p->scope, tmp + len + 1) != NULL) {
			tmp[len++] = '%';
			len += strlen(tmp + len);
		}

		ucv_stringbuf_addstr(buf, tmp, len);

		if (p->bits < AF_BITS(p->family))
			ucv_stringbuf_printf(buf, "/%d", p->bits);
	}

	return ucv_stringbuf_finish(buf);

err:
	ucv_put(ucv_stringbuf_finish(buf));

	return NULL;
}

/*
 * range value accessors
 */

static inline range_t *
get_this_range(uc_vm_t *vm)
{
	range_t **p = uc_fn_this(range_type);

	return p ? *p : NULL;
}

/* Accept a range instance or a string convertible to one, returning a pointer
 * to the internal range of the instance or to *out for parsed strings */
static range_t *
check_range(uc_vm_t *vm, uc_value_t *arg, range_t *out, int family)
{
	if (ucv_type(arg) == UC_RESOURCE) {
		void **p = ucv_resource_dataptr(arg, range_type);

		if (p && *(range_t **)p &&
		    (!family || (*(range_t **)p)->family == family))
			return *(range_t **)p;

		return NULL;
	}

	if (ucv_type(arg) == UC_STRING) {
		if (parse_range(ucv_string_get(arg), out) &&
		    (!family || out->family == family))
			return out;
	}

	return NULL;
}

static bool
check_bits(uc_vm_t *vm, uc_value_t *arg, range_t *p, int16_t *bits)
{
	uint64_t n;
	int16_t s16;

	if (arg == NULL) {
		*bits = p->bits;
		return true;
	}

	if (ucv_type(arg) == UC_INTEGER || ucv_type(arg) == UC_DOUBLE) {
		n = ucv_to_unsigned(arg);

		if (errno != 0 || n > AF_BITS(p->family))
			return false;

		*bits = (int16_t)n;
		return true;
	}

	if (ucv_type(arg) == UC_STRING) {
		if (!parse_mask(p->family, ucv_string_get(arg), &s16))
			return false;

		*bits = s16;
		return true;
	}

	return false;
}

static uc_value_t *
new_range(uc_vm_t *vm, range_t *rng)
{
	range_t *p = xalloc(sizeof(*p));

	*p = *rng;

	return ucv_resource_new(ucv_resource_type_lookup(vm, range_type), p);
}

/*
 * scope handling
 */

static uint32_t
parse_scope(uc_vm_t *vm, uc_value_t *scope, range_t *p, bool strict)
{
	uint32_t idx = (uint32_t)-1;

	/*
	 * the scope carries the interface the address is bound to; it is
	 * valid for MAC addresses and for IPv6 link-local addresses
	 * (fe80::/10), matching the %scope handling in parse_range()
	 */
	if (p->family == AF_PACKET ||
	    (p->family == AF_INET6 &&
	     p->addr.v6.s6_addr[0] == 0xFE &&
	     p->addr.v6.s6_addr[1] >= 0x80 &&
	     p->addr.v6.s6_addr[2] <= 0xBF)) {
		if (ucv_type(scope) == UC_INTEGER) {
			uint64_t n = ucv_to_unsigned(scope);

			/*
			 * like the socket module, the integer scope id is
			 * taken as-is without resolving it to an interface
			 */
			if (errno == 0 && n <= UINT32_MAX)
				idx = (uint32_t)n;
		}
		else if (ucv_type(scope) == UC_STRING) {
			idx = if_nametoindex(ucv_string_get(scope));
			idx = (idx == 0) ? (uint32_t)-1 : idx;
		}

		if (idx == (uint32_t)-1 && strict) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid scope");

			return 0;
		}
	}

	return idx;
}

/*
 * module functions
 */

static bool
parse_addr(uc_vm_t *vm, uc_value_t *addr, int family, range_t *out)
{
	uint64_t n;
	size_t i, len;

	if (ucv_type(addr) == UC_ARRAY) {
		int fam;

		switch (ucv_array_length(addr)) {
		case 4:
			fam = AF_INET;
			break;

		case 6:
			fam = AF_PACKET;
			break;

		case 16:
			fam = AF_INET6;
			break;

		default:
			return false;
		}

		if (family && family != fam)
			return false;

		out->family = fam;
		out->bits = AF_BITS(fam);

		for (i = 0, len = ucv_array_length(addr); i < len; i++) {
			uc_value_t *v = ucv_array_get(addr, i);

			if (ucv_type(v) != UC_INTEGER && ucv_type(v) != UC_DOUBLE)
				return false;

			n = ucv_to_unsigned(v);

			if (errno != 0 || n > 255)
				return false;

			out->addr.u8[i] = n;
		}

		return true;
	}

	if (ucv_type(addr) == UC_OBJECT) {
		/*
		 * sockaddr-like object: { family, address, interface }
		 *
		 * family:    optional, one of AF_INET, AF_INET6, AF_PACKET;
		 *            guessed from the address if omitted
		 * address:   mandatory address string
		 * interface: optional, AF_INET6 scope (name or index)
		 */
		uc_value_t *v, *addrv;
		char buf[INET6_ADDRSTRLEN * 2 + 2];
		bool found;
		int fam = family;

		addrv = ucv_object_get(addr, "address", &found);

		if (!found || ucv_type(addrv) != UC_STRING)
			return false;

		v = ucv_object_get(addr, "family", &found);

		if (found) {
			if (ucv_type(v) != UC_INTEGER)
				return false;

			switch (ucv_int64_get(v)) {
			case AF_INET:
			case AF_INET6:
			case AF_PACKET:
				fam = (int)ucv_int64_get(v);
				break;

			default:
				return false;
			}
		}
		else
			fam = (strchr(ucv_string_get(addrv), ':') != NULL)
			    ? AF_INET6 : AF_INET;

		if (family && family != fam)
			return false;

		if (ucv_string_length(addrv) + 1 > sizeof(buf))
			return false;

		memcpy(buf, ucv_string_get(addrv),
		       ucv_string_length(addrv) + 1);

		if (!parse_range(buf, out))
			return false;

		/* parse_range may have auto-detected a different family */
		if (out->family != fam)
			return false;

		v = ucv_object_get(addr, "interface", &found);

		if (found) {
			if (out->family != AF_INET6)
				return false;

			/*
			 * the scope is only valid for link-local addresses,
			 * matching the %scope handling in parse_range()
			 */
			if (!(out->addr.v6.s6_addr[0] == 0xFE &&
			      out->addr.v6.s6_addr[1] >= 0x80 &&
			      out->addr.v6.s6_addr[2] <= 0xBF))
				return false;

			out->scope = parse_scope(vm, v, out, true);
		}

		return true;
	}

	if (ucv_type(addr) == UC_INTEGER || ucv_type(addr) == UC_DOUBLE) {
		n = ucv_to_unsigned(addr);

		if (errno != 0)
			return false;

		switch (family) {
		case AF_INET:
			out->family = AF_INET;
			out->addr.v4.s_addr = htonl((uint32_t)n);
			break;

		case AF_INET6:
			out->family = AF_INET6;
			out->addr.v6.s6_addr[12] = n / 0x1000000;
			out->addr.v6.s6_addr[13] = n % 0x1000000 / 0x10000;
			out->addr.v6.s6_addr[14] = n % 0x10000 / 0x100;
			out->addr.v6.s6_addr[15] = n % 0x100;
			break;

		default:
			out->family = AF_PACKET;
			out->addr.mac[2] = n / 0x1000000;
			out->addr.mac[3] = n % 0x1000000 / 0x10000;
			out->addr.mac[4] = n % 0x10000 / 0x100;
			out->addr.mac[5] = n % 0x100;
			break;
		}

		out->bits = AF_BITS(out->family);
		return true;
	}

	if (ucv_type(addr) == UC_STRING &&
	    parse_range(ucv_string_get(addr), out) &&
	    (!family || out->family == family))
		return true;

	return false;
}

/**
 * Construct a new `netaddr.range` instance, auto-detecting the address family.
 *
 * Raises a runtime exception if the given argument does not represent a
 * valid address or if the given optional netmask is of a different family.
 *
 * @function module:netaddr#new
 *
 * @param {string|number|number[]|object} address
 * A valid IPv4 or IPv6 address, optionally with prefix size (CIDR notation)
 * or netmask separated by slash, an unsigned number, an array of bytes, or
 * a sockaddr-like object (see below).
 * Numbers are interpreted as MAC addresses, except when used with the
 * {@link module:netaddr#v4} or {@link module:netaddr#v6} constructors. The
 * address family of byte arrays is determined by their length: `4` for
 * IPv4, `6` for MAC and `16` for IPv6.
 *
 * A sockaddr-like object has the following properties:
 *
 * - `address` (string, mandatory): the address value
 * - `family` (number, optional): `AF_INET` (2), `AF_INET6` (10) or
 *   `AF_PACKET` (17, MAC); guessed from `address` if omitted
 * - `interface` (string|number, optional): scope for `AF_INET6` addresses,
 *   either an interface name or index
 *
 * @param {string|number} [netmask]
 * A valid IPv4 or IPv6 netmask or a number containing a prefix size in bits
 * (`0..32` for IPv4, `0..128` for IPv6). Overrides the mask embedded in the
 * first argument if specified.
 *
 * @returns {module:netaddr.range}
 *
 * @example
 * const addr = netaddr.new('10.24.0.1/24');
 * const addr = netaddr.new('10.24.0.1/255.255.255.0');
 * const addr = netaddr.new('10.24.0.1', '255.255.255.0');  // separate netmask
 * const addr = netaddr.new('10.24.0.1/24', 16);            // override netmask
 *
 * const addr6 = netaddr.new('fe80::221:63ff:fe75:aa17/64');
 * const addr6 = netaddr.new('fe80::221:63ff:fe75:aa17/ffff:ffff:ffff:ffff::');
 *
 * const mac = netaddr.new('00:11:22:cc:dd:ee');
 * const mac = netaddr.new(0x001122ccddeeff);
 *
 * const addr = netaddr.new([ 10, 24, 0, 1 ]);          // IPv4
 * const addr6 = netaddr.new([ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 ]);
 *
 * const addr = netaddr.new({ address: '10.24.0.1' });  // family guessed
 * const addr = netaddr.new({ family: 2, address: '10.24.0.1' });
 * const addr6 = netaddr.new({ family: 10, address: 'fe80::1', interface: 'lo' });
 */
static uc_value_t *
uc_netaddr_new(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *addr = uc_fn_arg(0);
	range_t rng = { };

	if (!parse_addr(vm, addr, 0, &rng)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Invalid address");

		return NULL;
	}

	/*
	 * Numbers cannot carry an embedded netmask, ignore the second
	 * constructor argument (matches the LuCI reference behavior).
	 */
	if (nargs > 1 && ucv_type(addr) == UC_STRING) {
		int16_t bits;

		if (!check_bits(vm, uc_fn_arg(1), &rng, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}

		rng.bits = bits;
	}

	return new_range(vm, &rng);
}

/**
 * Construct a new IPv4 `netaddr.range` instance.
 *
 * Raises a runtime exception if the given argument does not represent a
 * valid IPv4 address or if the given optional netmask is of a different
 * family.
 *
 * @function module:netaddr#v4
 *
 * @param {string|number|number[]|object} address
 * A valid IPv4 address, optionally with prefix size (CIDR notation) or
 * netmask separated by slash, an unsigned number representing the address
 * in host byte order, an array of exactly `4` bytes, or a sockaddr-like
 * object with `family` `AF_INET` (or an address guessed as IPv4).
 *
 * @param {string|number} [netmask]
 * A valid IPv4 netmask or a number containing a prefix size between `0`
 * and `32` bit. Overrides the mask embedded in the first argument if
 * specified.
 *
 * @returns {module:netaddr.range}
 *
 * @example
 * const addr = netaddr.IPv4('10.24.0.1/24');
 * const addr = netaddr.IPv4('10.24.0.1/255.255.255.0');
 * const addr = netaddr.IPv4('10.24.0.1', '255.255.255.0');  // separate netmask
 * const addr = netaddr.IPv4('10.24.0.1/24', 16);            // override netmask
 */
static uc_value_t *
uc_netaddr_v4(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *addr = uc_fn_arg(0);
	range_t rng = { };

	if (!parse_addr(vm, addr, AF_INET, &rng)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Invalid IPv4 address");

		return NULL;
	}

	if (nargs > 1 && ucv_type(addr) == UC_STRING) {
		int16_t bits;

		if (!check_bits(vm, uc_fn_arg(1), &rng, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}

		rng.bits = bits;
	}

	return new_range(vm, &rng);
}

/**
 * Construct a new IPv6 `netaddr.range` instance.
 *
 * Raises a runtime exception if the given argument does not represent a
 * valid IPv6 address or if the given optional netmask is of a different
 * family.
 *
 * @function module:netaddr#v6
 *
 * @param {string|number|number[]|object} address
 * A valid IPv6 address, optionally with prefix size (CIDR notation) or
 * netmask separated by slash, an unsigned number representing the last
 * 32 bit of the address, an array of exactly `16` bytes, or a
 * sockaddr-like object with `family` `AF_INET6` (or an address guessed as
 * IPv6), optionally carrying an `interface` scope.
 *
 * @param {string|number} [netmask]
 * A valid IPv6 netmask or a number containing a prefix size between `0`
 * and `128` bit. Overrides the mask embedded in the first argument if
 * specified.
 *
 * @param {string|number} [scope]
 * An optional address scope for link-local addresses (`fe80::/10`),
 * either an interface name or numeric index.
 *
 * @returns {module:netaddr.range}
 *
 * @example
 * const addr6 = netaddr.IPv6('fe80::221:63ff:fe75:aa17/64');
 * const addr6 = netaddr.IPv6('fe80::221:63ff:fe75:aa17/ffff:ffff:ffff:ffff::');
 * const addr6 = netaddr.IPv6('fe80::221:63ff:fe75:aa17', 'ffff:ffff:ffff:ffff::');
 * const addr6 = netaddr.IPv6('fe80::221:63ff:fe75:aa17/64', 128);  // override
 * const addr6 = netaddr.IPv6('fe80::221:63ff:fe75:aa17', 64, 'eth0');
 */
static uc_value_t *
uc_netaddr_v6(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *addr = uc_fn_arg(0);
	range_t rng = { };

	if (!parse_addr(vm, addr, AF_INET6, &rng)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Invalid IPv6 address");

		return NULL;
	}

	if (nargs > 1 && ucv_type(addr) == UC_STRING) {
		int16_t bits;

		if (!check_bits(vm, uc_fn_arg(1), &rng, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}

		rng.bits = bits;
	}

	if (nargs > 2 && ucv_type(addr) == UC_STRING) {
		uint32_t scope = parse_scope(vm, uc_fn_arg(2), &rng, true);

		if (scope != (uint32_t)-1)
			rng.scope = scope;
	}

	return new_range(vm, &rng);
}

/**
 * Construct a new MAC `netaddr.range` instance.
 *
 * Raises a runtime exception if the given argument does not represent a
 * valid ethernet MAC address or if the given optional mask is of a
 * different family.
 *
 * @function module:netaddr#mac
 *
 * @param {string|number|number[]|object} address
 * A valid ethernet MAC address, optionally with prefix size (CIDR
 * notation) or mask separated by slash, an unsigned number representing
 * the last 32 bit of the address, an array of exactly `6` bytes, or a
 * sockaddr-like object with `family` `AF_PACKET`.
 *
 * @param {string|number} [netmask]
 * A valid MAC address mask or a number containing a prefix size between
 * `0` and `48` bit. Overrides the mask embedded in the first argument if
 * specified.
 *
 * @returns {module:netaddr.range}
 *
 * @example
 * const intel_macs = netaddr.MAC('C0:B6:F9:00:00:00/24');
 * const intel_macs = netaddr.MAC('C0:B6:F9:00:00:00/FF:FF:FF:0:0:0');
 * const intel_macs = netaddr.MAC('C0:B6:F9:00:00:00', 'FF:FF:FF:0:0:0');
 * const intel_macs = netaddr.MAC('C0:B6:F9:00:00:00/24', 48);  // override mask
 */
static uc_value_t *
uc_netaddr_mac(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *addr = uc_fn_arg(0);
	range_t rng = { };

	if (!parse_addr(vm, addr, AF_PACKET, &rng)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
		                      "Invalid MAC address");

		return NULL;
	}

	if (nargs > 1 && ucv_type(addr) == UC_STRING) {
		int16_t bits;

		if (!check_bits(vm, uc_fn_arg(1), &rng, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}

		rng.bits = bits;
	}

	return new_range(vm, &rng);
}

static uc_value_t *
uc_netaddr_check(uc_vm_t *vm, size_t nargs, int family)
{
	uc_value_t *arg = uc_fn_arg(0);
	range_t rng = { };

	if (ucv_type(arg) == UC_RESOURCE) {
		void **p = ucv_resource_dataptr(arg, range_type);

		if (!p || !*(range_t **)p || (*(range_t **)p)->family != family)
			return NULL;

		return format_range(vm, *(range_t **)p);
	}

	if (ucv_type(arg) == UC_STRING &&
	    parse_range(ucv_string_get(arg), &rng) &&
	    rng.family == family)
		return format_range(vm, &rng);

	return NULL;
}

/**
 * Verify an IPv4 address.
 *
 * Checks whether the given argument is a preexisting `netaddr.range` IPv4 address
 * instance or a string literal convertible to an IPv4 address and returns a
 * plain string containing the canonical representation of the address.
 *
 * Returns `null` if the argument is not a valid IPv4 address. This function
 * is intended to aid in safely verifying address literals without having to
 * deal with exceptions.
 *
 * @function module:netaddr#checkv4
 *
 * @param {string|module:netaddr.range} address
 * A valid IPv4 address or existing `netaddr.range` IPv4 instance.
 *
 * @returns {?string}
 *
 * @example
 * netaddr.checkv4(netaddr.new('127.0.0.1'));  // "127.0.0.1"
 * netaddr.checkv4('127.0.0.1');          // "127.0.0.1"
 * netaddr.checkv4('nonsense');           // null
 * netaddr.checkv4(123);                  // null
 * netaddr.checkv4(null);                 // null
 */
static uc_value_t *
uc_netaddr_checkv4(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_check(vm, nargs, AF_INET);
}

/**
 * Verify an IPv6 address.
 *
 * Checks whether the given argument is a preexisting `netaddr.range` IPv6 address
 * instance or a string literal convertible to an IPv6 address and returns a
 * plain string containing the canonical representation of the address.
 *
 * Returns `null` if the argument is not a valid IPv6 address. This function
 * is intended to aid in safely verifying address literals without having to
 * deal with exceptions.
 *
 * @function module:netaddr#checkv6
 *
 * @param {string|module:netaddr.range} address
 * A valid IPv6 address or existing `netaddr.range` IPv6 instance.
 *
 * @returns {?string}
 *
 * @example
 * netaddr.checkv6(netaddr.new('0:0:0:0:0:0:0:1'));  // "::1"
 * netaddr.checkv6('0:0:0:0:0:0:0:1');          // "::1"
 * netaddr.checkv6('nonsense');                 // null
 * netaddr.checkv6(123);                        // null
 * netaddr.checkv6(null);                       // null
 */
static uc_value_t *
uc_netaddr_checkv6(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_check(vm, nargs, AF_INET6);
}

/**
 * Verify an ethernet MAC address.
 *
 * Checks whether the given argument is a preexisting `netaddr.range` MAC address
 * instance or a string literal convertible to an ethernet MAC and returns a
 * plain string containing the canonical representation of the address.
 *
 * Returns `null` if the argument is not a valid MAC address. This function
 * is intended to aid in safely verifying address literals without having to
 * deal with exceptions.
 *
 * @function module:netaddr#checkmac
 *
 * @param {string|module:netaddr.range} address
 * A valid MAC address or existing `netaddr.range` MAC instance.
 *
 * @returns {?string}
 *
 * @example
 * netaddr.checkmac(netaddr.new('00-11-22-cc-dd-ee'));  // "00:11:22:CC:DD:EE"
 * netaddr.checkmac('00:11:22:cc:dd:ee');          // "00:11:22:CC:DD:EE"
 * netaddr.checkmac('nonsense');                   // null
 * netaddr.checkmac(123);                          // null
 * netaddr.checkmac(null);                         // null
 */
static uc_value_t *
uc_netaddr_checkmac(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_check(vm, nargs, AF_PACKET);
}

/*
 * range methods
 */

/**
 * Represents an IP address or address range as created by `new()`,
 * `v4()`, `v6()` or `mac()`.
 *
 * Instances carry the address, its family (`4` for IPv4, `6` for IPv6
 * and `1` for MAC addresses) and a prefix size in bits (`32` for IPv4,
 * `128` for IPv6 and `48` for MAC addresses by default).
 *
 * Instances provide a `tostring()` method which is also used by `print()`
 * and string interpolation to render the address in canonical form,
 * including the prefix size if it is smaller than the family's full width.
 *
 * In addition, instances support property access through `__get__()` and
 * `__set__()` metamethods:
 *
 * - Numeric keys read or write the individual address bytes, e.g.
 *   `addr[0]` reads the first address byte and `addr[0] = 10` rewrites it.
 *   Negative indices count from the end of the address.
 * - The `bits` property reads or writes the prefix size in bits.
 * - The `family` property reads the address family (numeric `AF_*` value).
 * - The `scope` property reads or writes the address scope (the numeric
 *   interface index) for IPv6 and MAC address instances.
 * - The `scopeid` property reads or writes the address scope given an
 *   interface name or numeric index, silently ignoring non-link-local
 *   IPv6 addresses.
 * - The `netmask` property reads the netmask as a string, e.g.
 *   `"255.255.255.0"` for a `/24` prefix.
 * - The `host` property reads the host address as a new range (full-width
 *   prefix).
 * - The `mapped4` property reads the mapped IPv4 address as a new range,
 *   or `null` if the instance is not an IPv6 mapped IPv4 address.
 * - The `unscopename` property reads the interface name of the address
 *   scope (or an empty string if no scope is set).
 * - The `size` property reads the number of addresses in this range, or
 *   `null` if the value does not fit into a 64 bit signed integer.
 *
 * @class module:netaddr.range
 * @hideconstructor
 *
 * @property {number} bits
 * The prefix size in bits (read/write). `32` for IPv4, `128` for IPv6,
 * `48` for MAC addresses.
 *
 * @property {number} family
 * The address family (read-only): `4` for IPv4, `6` for IPv6,
 * `1` for MAC addresses.
 *
 * @property {number} scope
 * The address scope as a numeric interface index (read/write).
 * Only meaningful for IPv6 and MAC address instances.
 *
 * @property {?string} scopeid
 * The address scope as an interface name (read/write). Accepts an
 * interface name or numeric index for assignment. `null` if no scope
 * is set. Only meaningful for IPv6 and MAC address instances.
 *
 * @property {string} netmask
 * The netmask as a string, e.g. `"255.255.255.0"` (read-only).
 *
 * @property {module:netaddr.range} host
 * The host address as a new range with a full-width prefix (read-only).
 *
 * @property {?module:netaddr.range} mapped4
 * The mapped IPv4 address as a new range, or `null` if the instance
 * is not an IPv6 mapped IPv4 address (read-only).
 *
 * @property {string} unscopename
 * The interface name of the address scope, or an empty string if no
 * scope is set (read-only).
 *
 * @property {?number} size
 * The number of addresses in this range, or `null` if the value does
 * not fit into a 64 bit signed integer (read-only).
 *
 * @see {@link module:netaddr#new|new()}
 * @see {@link module:netaddr#v4|v4()}
 * @see {@link module:netaddr#v6|v6()}
 * @see {@link module:netaddr#mac|mac()}
 *
 * @example
 *
 * const addr = netaddr.new('192.168.1.1/24');
 *
 * addr.is4();        // true
 * addr.network();    // "192.168.1.0"
 * addr.maxhost();    // "192.168.1.254"
 *
 * addr.bits;         // 24
 * addr[0];           // 192
 * addr.netmask;      // "255.255.255.0"
 * addr.host;         // netaddr.range "192.168.1.1"
 * addr.size;         // 256
 *
 * addr[3] = 10;      // "192.168.1.10/24"
 * addr.bits = 16;    // "192.168.0.0/16"
 *
 * print(addr);       // "192.168.0.0/16"
 */

/**
 * Checks whether the CIDR instance is an IPv4 address range.
 *
 * @function module:netaddr.range#is4
 *
 * @returns {boolean} `true` if the CIDR is an IPv4 range, else `false`
 */
static uc_value_t *
uc_netaddr_range_is4(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new(p->family == AF_INET);
}

/**
 * Checks whether the CIDR instance is within the private RFC1918 address
 * space.
 *
 * @function module:netaddr.range#is4rfc1918
 *
 * @returns {boolean} `true` if the entire range of this CIDR lies within
 * one of the ranges `10.0.0.0-10.255.255.255`, `172.16.0.0-172.31.0.0` or
 * `192.168.0.0-192.168.255.255`, else `false`
 *
 * @example
 * const addr = netaddr.new('192.168.45.2/24');
 * addr.is4rfc1918();  // true
 */
static uc_value_t *
uc_netaddr_range_is4rfc1918(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	uint32_t a = htonl(p->addr.v4.s_addr);

	return ucv_boolean_new((p->family == AF_INET &&
	                    ((a >= 0x0A000000 && a <= 0x0AFFFFFF) ||
	                     (a >= 0xAC100000 && a <= 0xAC1FFFFF) ||
	                     (a >= 0xC0A80000 && a <= 0xC0A8FFFF))));
}

/**
 * Checks whether the CIDR instance is an IPv4 link local (Zeroconf)
 * address.
 *
 * @function module:netaddr.range#is4linklocal
 *
 * @returns {boolean} `true` if the entire range of this CIDR lies within
 * the range `169.254.0.0-169.254.255.255`, else `false`
 *
 * @example
 * const addr = netaddr.new('169.254.34.125');
 * addr.is4linklocal();  // true
 */
static uc_value_t *
uc_netaddr_range_is4linklocal(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	uint32_t a = htonl(p->addr.v4.s_addr);

	return ucv_boolean_new((p->family == AF_INET &&
	                    a >= 0xA9FE0000 &&
	                    a <= 0xA9FEFFFF));
}

/**
 * Checks whether the CIDR instance is an IPv6 address range.
 *
 * @function module:netaddr.range#is6
 *
 * @returns {boolean} `true` if the CIDR is an IPv6 range, else `false`
 */
static uc_value_t *
uc_netaddr_range_is6(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new(p->family == AF_INET6);
}

/**
 * Checks whether the CIDR instance is an IPv6 link local address.
 *
 * @function module:netaddr.range#is6linklocal
 *
 * @returns {boolean} `true` if the entire range of this CIDR lies within
 * the `fe80::/10` range, else `false`
 *
 * @example
 * const addr = netaddr.new('fe92:53a:3216:af01:221:63ff:fe75:aa17/64');
 * addr.is6linklocal();  // true
 */
static uc_value_t *
uc_netaddr_range_is6linklocal(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new((p->family == AF_INET6 &&
	                    p->addr.v6.s6_addr[0] == 0xFE &&
	                    p->addr.v6.s6_addr[1] >= 0x80 &&
	                    p->addr.v6.s6_addr[1] <= 0xBF));
}

static bool
is_mapped4(range_t *p)
{
	return (p->family == AF_INET6 &&
	        p->addr.v6.s6_addr[0] == 0 &&
	        p->addr.v6.s6_addr[1] == 0 &&
	        p->addr.v6.s6_addr[2] == 0 &&
	        p->addr.v6.s6_addr[3] == 0 &&
	        p->addr.v6.s6_addr[4] == 0 &&
	        p->addr.v6.s6_addr[5] == 0 &&
	        p->addr.v6.s6_addr[6] == 0 &&
	        p->addr.v6.s6_addr[7] == 0 &&
	        p->addr.v6.s6_addr[8] == 0 &&
	        p->addr.v6.s6_addr[9] == 0 &&
	        p->addr.v6.s6_addr[10] == 0xFF &&
	        p->addr.v6.s6_addr[11] == 0xFF);
}

/**
 * Checks whether the CIDR instance is an IPv6 mapped IPv4 address.
 *
 * @function module:netaddr.range#is6mapped4
 *
 * @returns {boolean} `true` if the address is an IPv6 mapped IPv4 address
 * in the form `::ffff:1.2.3.4`
 *
 * @example
 * const addr = netaddr.new('::ffff:192.168.1.1');
 * addr.is6mapped4();  // true
 */
static uc_value_t *
uc_netaddr_range_is6mapped4(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new(is_mapped4(p));
}

/**
 * Checks whether the CIDR instance is an ethernet MAC address range.
 *
 * @function module:netaddr.range#ismac
 *
 * @returns {boolean} `true` if the CIDR is a MAC address range, else
 * `false`
 */
static uc_value_t *
uc_netaddr_range_ismac(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new(p->family == AF_PACKET);
}

/**
 * Checks whether the CIDR instance is a locally administered (LAA) MAC
 * address.
 *
 * @function module:netaddr.range#ismaclocal
 *
 * @returns {boolean} `true` if the MAC address sets the locally
 * administered bit
 *
 * @example
 * const mac = netaddr.new('02:C0:FF:EE:00:01');
 * mac.ismaclocal();  // true
 */
static uc_value_t *
uc_netaddr_range_ismaclocal(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new((p->family == AF_PACKET &&
	                    (p->addr.mac[0] & 0x2)));
}

/**
 * Checks whether the CIDR instance is a multicast MAC address.
 *
 * @function module:netaddr.range#ismacmcast
 *
 * @returns {boolean} `true` if the MAC address sets the multicast bit
 *
 * @example
 * const mac = netaddr.new('01:00:5E:7F:00:10');
 * mac.ismacmcast();  // true
 */
static uc_value_t *
uc_netaddr_range_ismacmcast(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return ucv_boolean_new((p->family == AF_PACKET &&
	                    (p->addr.mac[0] & 0x1)));
}

static int
range_cmp(range_t *a, range_t *b)
{
	if (a->family != b->family)
		return (a->family - b->family);

	return memcmp(&a->addr.v6, &b->addr.v6, AF_BYTES(a->family));
}

/**
 * Checks whether this CIDR instance is lower than the given argument.
 *
 * The comparison follows these rules:
 *
 * - An IPv4 address is always lower than an IPv6 address and IPv6
 *   addresses are considered lower than MAC addresses
 * - Prefix sizes are ignored
 *
 * @function module:netaddr.range#lower
 *
 * @param {string|module:netaddr.range} addr
 * An `netaddr.range` instance or a string convertible by `new()` to compare
 * against.
 *
 * @returns {?boolean} `true` if this CIDR is lower than the given
 * address, else `false`. Returns `null` if the argument cannot be
 * converted to a CIDR instance.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1');
 * addr.lower(addr);                         // false
 * addr.lower('10.10.10.10/24');             // false
 * addr.lower(netaddr.new('::1'));                // true
 * addr.lower(netaddr.new('192.168.200.1'));      // true
 * addr.lower(netaddr.new('00:14:22:01:23:45'));  // true
 */
static uc_value_t *
uc_netaddr_range_lower(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	range_t b = { };
	range_t *bptr;

	bptr = check_range(vm, uc_fn_arg(0), &b, 0);

	if (!bptr)
		return NULL;

	return ucv_boolean_new(range_cmp(p, bptr) < 0);
}

/**
 * Checks whether this CIDR instance is higher than the given argument.
 *
 * The comparison follows these rules:
 *
 * - An IPv4 address is always lower than an IPv6 address and IPv6
 *   addresses are considered lower than MAC addresses
 * - Prefix sizes are ignored
 *
 * @function module:netaddr.range#higher
 *
 * @param {string|module:netaddr.range} addr
 * An `netaddr.range` instance or a string convertible by `new()` to compare
 * against.
 *
 * @returns {?boolean} `true` if this CIDR is higher than the given
 * address, else `false`. Returns `null` if the argument cannot be
 * converted to a CIDR instance.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1');
 * addr.higher(addr);                        // false
 * addr.higher('10.10.10.10/24');            // true
 * addr.higher(netaddr.new('::1'));               // false
 * addr.higher(netaddr.new('192.168.200.1'));     // false
 * addr.higher(netaddr.new('00:14:22:01:23:45')); // false
 */
static uc_value_t *
uc_netaddr_range_higher(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	range_t b = { };
	range_t *bptr;

	bptr = check_range(vm, uc_fn_arg(0), &b, 0);

	if (!bptr)
		return NULL;

	return ucv_boolean_new(range_cmp(p, bptr) > 0);
}

/**
 * Checks whether this CIDR instance is equal to the given argument.
 *
 * @function module:netaddr.range#equal
 *
 * @param {string|module:netaddr.range} addr
 * An `netaddr.range` instance or a string convertible by `new()` to compare
 * against.
 *
 * @returns {?boolean} `true` if this CIDR is equal to the given address,
 * else `false`. Returns `null` if the argument cannot be converted to a
 * CIDR instance.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1');
 * addr.equal(addr);                 // true
 * addr.equal('192.168.1.1');        // true
 * addr.equal(netaddr.new('::1'));        // false
 *
 * const addr6 = netaddr.new('::1');
 * addr6.equal('0:0:0:0:0:0:0:1/64');  // true
 *
 * const mac = netaddr.new('00:14:22:01:23:45');
 * mac.equal('0:14:22:1:23:45');  // true
 */
static uc_value_t *
uc_netaddr_range_equal(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	range_t b = { };
	range_t *bptr;

	bptr = check_range(vm, uc_fn_arg(0), &b, 0);

	if (!bptr)
		return NULL;

	return ucv_boolean_new(range_cmp(p, bptr) == 0);
}

/**
 * Get or set the prefix size of this CIDR instance.
 *
 * If the optional mask parameter is given, the prefix size of this CIDR is
 * altered, else the current prefix size is returned.
 *
 * @function module:netaddr.range#prefix
 *
 * @param {number|string} [mask]
 * A number containing the number of bits (`0..32` for IPv4, `0..128` for
 * IPv6 or `0..48` for MAC addresses) or a string containing a valid
 * netmask.
 *
 * @returns {number} The bit count of the (new) prefix size
 *
 * @example
 * const range = netaddr.new('192.168.1.1/255.255.255.0');
 * range.prefix();  // 24
 *
 * range.prefix(16);
 * range.prefix();  // 16
 *
 * range.prefix('255.255.255.255');
 * range.prefix();  // 32
 */
static uc_value_t *
uc_netaddr_range_prefix(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	int16_t bits;

	if (nargs > 0) {
		if (!check_bits(vm, uc_fn_arg(0), p, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}

		p->bits = bits;
	}

	return ucv_int64_new(p->bits);
}

static void
apply_mask(range_t *p, int bits, bool inv)
{
	uint8_t b, i;

	if (bits <= 0) {
		memset(&p->addr.u8, inv * 0xFF, AF_BYTES(p->family));
	}
	else if (p->family == AF_INET && bits <= AF_BITS(AF_INET)) {
		if (inv)
			p->addr.v4.s_addr |= ntohl((1 << (AF_BITS(AF_INET) - bits)) - 1);
		else
			p->addr.v4.s_addr &= ntohl(~((1 << (AF_BITS(AF_INET) - bits)) - 1));
	}
	else if (bits <= AF_BITS(p->family)) {
		for (i = 0; i < AF_BYTES(p->family); i++) {
			b = (bits > 8) ? 8 : bits;
			if (inv)
				p->addr.u8[i] |= ~((uint8_t)(0xFF << (8 - b)));
			else
				p->addr.u8[i] &= (uint8_t)(0xFF << (8 - b));
			bits -= b;
		}
	}
}

/**
 * Derive the network address of this CIDR instance.
 *
 * Returns a new CIDR instance representing the network address of this
 * instance with all host parts masked out. The used prefix size can be
 * overridden by the optional mask parameter.
 *
 * @function module:netaddr.range#network
 *
 * @param {number|string} [mask]
 * A number containing the number of bits (`0..32` for IPv4, `0..128` for
 * IPv6 or `0..48` for MAC addresses) or a string containing a valid
 * netmask.
 *
 * @returns {module:netaddr.range} A CIDR instance representing the network
 * address
 *
 * @example
 * const range = netaddr.new('192.168.62.243/255.255.0.0');
 * range.network();                // "192.168.0.0"
 * range.network(24);              // "192.168.62.0"
 * range.network('255.255.255.0'); // "192.168.62.0"
 *
 * const range6 = netaddr.new('fd9b:62b3:9cc5:0:221:63ff:fe75:aa17/64');
 * range6.network();               // "fd9b:62b3:9cc5::"
 */
static uc_value_t *
uc_netaddr_range_network(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2 = *p1;
	int16_t bits;

	if (nargs > 0) {
		if (!check_bits(vm, uc_fn_arg(0), p1, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}
	}
	else {
		bits = p1->bits;
	}

	p2.bits = AF_BITS(p1->family);
	apply_mask(&p2, bits, false);

	return new_range(vm, &p2);
}

/**
 * Derive the netmask of this CIDR instance.
 *
 * Constructs a CIDR instance representing the netmask of this instance.
 * The used prefix size can be overridden by the optional mask parameter.
 *
 * @function module:netaddr.range#mask
 *
 * @param {number|string} [mask]
 * A number containing the number of bits (`0..32` for IPv4, `0..128` for
 * IPv6 or `0..48` for MAC addresses) or a string containing a valid
 * netmask.
 *
 * @returns {module:netaddr.range} A CIDR instance representing the netmask
 *
 * @example
 * const range = netaddr.new('172.19.37.45/16');
 * range.mask();            // "255.255.0.0"
 * range.mask(24);          // "255.255.255.0"
 * range.mask('255.0.0.0'); // "255.0.0.0"
 */
static uc_value_t *
uc_netaddr_range_mask(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2 = { };
	int16_t bits;

	if (nargs > 0) {
		if (!check_bits(vm, uc_fn_arg(0), p1, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}
	}
	else {
		bits = p1->bits;
	}

	p2.scope = 0;
	p2.bits = AF_BITS(p1->family);
	p2.family = p1->family;

	memset(&p2.addr.v6.s6_addr, 0xFF, sizeof(p2.addr.v6.s6_addr));
	apply_mask(&p2, bits, false);

	return new_range(vm, &p2);
}

/**
 * Derive the broadcast address of this CIDR instance.
 *
 * Constructs a CIDR instance representing the broadcast address of this
 * instance. The used prefix size can be overridden by the optional mask
 * parameter.
 *
 * This function has no effect on IPv6 or MAC address instances, it will
 * return `null` in this case.
 *
 * @function module:netaddr.range#broadcast
 *
 * @param {number|string} [mask]
 * A number containing the number of bits (`0..32` for IPv4) or a string
 * containing a valid netmask.
 *
 * @returns {?module:netaddr.range} A new CIDR instance representing the
 * broadcast address if this instance is an IPv4 range, else `null`
 *
 * @example
 * const range = netaddr.new('172.19.37.45/16');
 * range.broadcast();            // "172.19.255.255"
 * range.broadcast(24);          // "172.19.37.255"
 * range.broadcast('255.0.0.0'); // "172.255.255.255"
 */
static uc_value_t *
uc_netaddr_range_broadcast(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2;
	int16_t bits;

	if (p1->family != AF_INET)
		return NULL;

	if (nargs > 0) {
		if (!check_bits(vm, uc_fn_arg(0), p1, &bits)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "Invalid netmask");

			return NULL;
		}
	}
	else {
		bits = p1->bits;
	}

	p2 = *p1;
	p2.bits = AF_BITS(AF_INET);
	apply_mask(&p2, bits, true);

	return new_range(vm, &p2);
}

/**
 * Derive the scoped address of this CIDR instance.
 *
 * Constructs a copy of the given IPv6 or MAC address instance carrying
 * the associated address scope, if any.
 *
 * This function has no effect on IPv4 instances, it will return `null`
 * in this case. If no scope is associated with the address, `null` is
 * returned.
 *
 * @function module:netaddr.range#scoped
 *
 * @returns {?module:netaddr.range} A new CIDR instance representing the
 * scoped address
 *
 * @example
 * const addr = netaddr.new('fe80::1234');
 * addr.scope = 2;
 * addr.scoped();  // "fe80::1234%eth0"  (if index 2 is eth0)
 */
static uc_value_t *
uc_netaddr_range_scoped(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2;

	if (p1->family == AF_INET || p1->scope == 0)
		return NULL;

	p2 = *p1;

	return new_range(vm, &p2);
}
/**
 * Derive the unscoped IPv6 address of this CIDR instance.
 *
 * Constructs a copy of the given IPv6 CIDR instance and drops the
 * associated address scope information.
 *
 * This function has no effect on IPv4 instances or MAC address instances,
 * it will return `null` in this case.
 *
 * @function module:netaddr.range#unscoped
 *
 * @returns {?module:netaddr.range} A new CIDR instance representing the
 * unscoped IPv6 address
 *
 * @example
 * const addr = netaddr.new('fe80::1234%eth0');
 * addr.unscoped();  // "fe80::1234"
 */
static uc_value_t *
uc_netaddr_range_unscoped(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2;

	if (p1->family != AF_INET6)
		return NULL;

	p2 = *p1;
	p2.scope = 0;

	return new_range(vm, &p2);
}

/**
 * Derive the MAC address of this IPv6 link local CIDR instance.
 *
 * Constructs a CIDR instance representing the MAC address contained in the
 * IPv6 link local address of this instance.
 *
 * This function has no effect on IPv4 instances, MAC address instances or
 * IPv6 instances which are not a link local address, it will return `null`
 * in this case.
 *
 * @function module:netaddr.range#tomac
 *
 * @returns {?module:netaddr.range} A new CIDR instance representing the MAC
 * address if this instance is an IPv6 link local address, else `null`
 *
 * @example
 * const addr = netaddr.new('fe80::6666:b3ff:fe47:e1b9');
 * addr.tomac();  // "64:66:B3:47:E1:B9"
 */
static uc_value_t *
uc_netaddr_range_tomac(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2 = { };

	if (p1->family != AF_INET6 ||
	    p1->addr.u8[0] != 0xFE ||
	    p1->addr.u8[1] != 0x80 ||
	    p1->addr.u8[2] != 0x00 ||
	    p1->addr.u8[3] != 0x00 ||
	    p1->addr.u8[4] != 0x00 ||
	    p1->addr.u8[5] != 0x00 ||
	    p1->addr.u8[6] != 0x00 ||
	    p1->addr.u8[7] != 0x00 ||
	    p1->addr.u8[11] != 0xFF ||
	    p1->addr.u8[12] != 0xFE)
		return NULL;

	p2.scope = 0;
	p2.family = AF_PACKET;
	p2.bits = AF_BITS(AF_PACKET);
	p2.addr.u8[0] = p1->addr.u8[8] ^ 0x02;
	p2.addr.u8[1] = p1->addr.u8[9];
	p2.addr.u8[2] = p1->addr.u8[10];
	p2.addr.u8[3] = p1->addr.u8[13];
	p2.addr.u8[4] = p1->addr.u8[14];
	p2.addr.u8[5] = p1->addr.u8[15];

	return new_range(vm, &p2);
}

/**
 * Derive the IPv6 link local address from this MAC address CIDR instance.
 *
 * Constructs a CIDR instance representing the IPv6 link local address of
 * the MAC address represented by this instance.
 *
 * This function has no effect on IPv4 instances or IPv6 instances, it will
 * return `null` in this case.
 *
 * @function module:netaddr.range#tolinklocal
 *
 * @returns {?module:netaddr.range} A new CIDR instance representing the IPv6
 * link local address
 *
 * @example
 * const mac = netaddr.new('64:66:B3:47:E1:B9');
 * mac.tolinklocal();  // "fe80::6666:b3ff:fe47:e1b9"
 */
static uc_value_t *
uc_netaddr_range_tolinklocal(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t p2 = { };

	if (p1->family != AF_PACKET)
		return NULL;

	p2.scope = p1->scope;
	p2.family = AF_INET6;
	p2.bits = AF_BITS(AF_INET6);
	p2.addr.u8[0] = 0xFE;
	p2.addr.u8[1] = 0x80;
	p2.addr.u8[2] = 0x00;
	p2.addr.u8[3] = 0x00;
	p2.addr.u8[4] = 0x00;
	p2.addr.u8[5] = 0x00;
	p2.addr.u8[6] = 0x00;
	p2.addr.u8[7] = 0x00;
	p2.addr.u8[8] = p1->addr.u8[0] ^ 0x02;
	p2.addr.u8[9] = p1->addr.u8[1];
	p2.addr.u8[10] = p1->addr.u8[2];
	p2.addr.u8[11] = 0xFF;
	p2.addr.u8[12] = 0xFE;
	p2.addr.u8[13] = p1->addr.u8[3];
	p2.addr.u8[14] = p1->addr.u8[4];
	p2.addr.u8[15] = p1->addr.u8[5];

	return new_range(vm, &p2);
}

/**
 * Test whether this CIDR contains the given range.
 *
 * @function module:netaddr.range#contains
 *
 * @param {string|module:netaddr.range} addr
 * An `netaddr.range` instance or a string convertible by `new()` to test.
 *
 * @returns {?boolean} `true` if this instance fully contains the given
 * address, else `false`. Returns `null` if the argument cannot be
 * converted to a CIDR instance.
 *
 * @example
 * const range = netaddr.new('10.24.0.0/255.255.0.0');
 * range.contains('10.24.5.1');  // true
 * range.contains('::1');        // false
 * range.contains('10.0.0.0/8'); // false
 *
 * const range6 = netaddr.new('fe80::/10');
 * range6.contains('fe80::221:63f:fe75:aa17/64');         // true
 * range6.contains('fd9b:6b3:c5:0:221:63f:fe75:aa17/64'); // false
 *
 * const intel_macs = netaddr.MAC('C0:B6:F9:00:00:00/24');
 * intel_macs.contains('C0:B6:F9:A3:C:11');  // true
 * intel_macs.contains('64:66:B3:47:E1:B9'); // false
 */
static uc_value_t *
uc_netaddr_range_contains(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t b = { };
	range_t *p2;
	range_t a = *p1;
	bool rv = false;

	p2 = check_range(vm, uc_fn_arg(0), &b, 0);

	if (p2 && p1->family == p2->family && p1->bits <= p2->bits) {
		apply_mask(&a, p1->bits, false);
		apply_mask(p2, p1->bits, false);

		rv = !memcmp(&a.addr.v6, &p2->addr.v6, AF_BYTES(a.family));
	}

	return ucv_boolean_new(rv);
}

#define BYTE(a, i) \
	(a)->addr.u8[AF_BYTES((a)->family) - (i) - 1]

static uc_value_t *
uc_netaddr_range_add_sub(uc_vm_t *vm, size_t nargs, bool add)
{
	range_t *p1 = get_this_range(vm);
	uc_value_t *arg = uc_fn_arg(0);
	range_t b = { };
	range_t *p2;
	range_t r = *p1;
	bool inplace = (nargs > 1 && ucv_type(uc_fn_arg(1)) == UC_BOOLEAN &&
	                ucv_boolean_get(uc_fn_arg(1)));
	bool ok = true;
	uint8_t i, carry;
	uint32_t a, b32;

	p2 = check_range(vm, arg, &b, p1->family);

	if (p2) {
		if (p1->family == AF_INET) {
			a = ntohl(p1->addr.v4.s_addr);
			b32 = ntohl(p2->addr.v4.s_addr);

			/* would over/underflow */
			if ((add && (UINT32_MAX - a) < b32) || (!add && a < b32)) {
				r.addr.v4.s_addr = add ? htonl(0xFFFFFFFF) : htonl(0);
				ok = false;
			}
			else {
				r.addr.v4.s_addr = add ? htonl(a + b32) : htonl(a - b32);
			}
		}
		else {
			for (i = 0, carry = 0; i < AF_BYTES(p1->family); i++) {
				if (add) {
					BYTE(&r, i) = BYTE(p1, i) + BYTE(p2, i) + carry;
					carry = (BYTE(p1, i) + BYTE(p2, i) + carry) / 256;
				}
				else {
					BYTE(&r, i) = (uint8_t)(BYTE(p1, i) - BYTE(p2, i) - carry);
					carry = (BYTE(p1, i) < (BYTE(p2, i) + carry));
				}
			}

			/* would over/underflow */
			if (carry) {
				memset(&r.addr.u8, add ? 0xFF : 0x00, AF_BYTES(r.family));
				ok = false;
			}
		}
	}
	else if (ucv_type(arg) == UC_INTEGER || ucv_type(arg) == UC_DOUBLE) {
		uint64_t n = ucv_to_unsigned(arg);

		if (errno != 0 ||
		    (AF_BITS(p1->family) < 64
		     && n > (1ULL << AF_BITS(p1->family)) - 1)) {
			memset(&r.addr.u8, add ? 0xFF : 0x00, AF_BYTES(p1->family));
			ok = false;
		}
		else if (p1->family == AF_INET) {
			uint32_t a = ntohl(p1->addr.v4.s_addr);

			if ((add && (UINT32_MAX - a) < n) || (!add && a < n)) {
				r.addr.v4.s_addr = add ? htonl(0xFFFFFFFF) : htonl(0);
				ok = false;
			}
			else {
				r.addr.v4.s_addr = add ? htonl(a + (uint32_t)n)
				                       : htonl(a - (uint32_t)n);
			}
		}
		else {
			for (i = 0, carry = 0; i < AF_BYTES(p1->family); i++) {
				uint8_t d = (uint8_t)(n & 0xFF);

				if (add) {
					BYTE(&r, i) = BYTE(p1, i) + d + carry;
					carry = (BYTE(p1, i) + d + carry) / 256;
				}
				else {
					BYTE(&r, i) = (uint8_t)(BYTE(p1, i) - d - carry);
					carry = (BYTE(p1, i) < (d + carry));
				}

				n >>= 8;
			}

			if (carry) {
				memset(&r.addr.u8, add ? 0xFF : 0x00, AF_BYTES(r.family));
				ok = false;
			}
		}
	}
	else {
		return NULL;
	}

	if (inplace) {
		*p1 = r;
		return ucv_boolean_new(ok);
	}

	return new_range(vm, &r);
}

/**
 * Add the given amount to this CIDR instance. If the result would overflow
 * the maximum address space, the result is set to the highest possible
 * address.
 *
 * @function module:netaddr.range#add
 *
 * @param {number|string|module:netaddr.range} amount
 * A numeric value, an `netaddr.range` instance or a string convertible by
 * `new()`.
 *
 * @param {boolean} [inplace]
 * If `true`, modify this instance instead of returning a new derived CIDR
 * instance.
 *
 * @returns {module:netaddr.range|boolean|null}
 * When adding inplace: `true` if the addition succeeded or `false` when
 * the addition overflowed. When deriving a new CIDR: a new instance
 * representing the value of this instance plus the added amount or the
 * highest possible address if the addition overflowed the available
 * address space. Returns `null` if the amount argument is not
 * convertible.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1/24');
 * addr.add(250);          // "192.168.1.251/24"
 * addr.add('0.0.99.0');   // "192.168.100.1/24"
 *
 * addr.add(256, true);    // true
 * addr;                   // "192.168.2.1/24"
 *
 * addr.add('255.0.0.0', true);  // false (overflow)
 * addr;                         // "255.255.255.255/24"
 *
 * const addr6 = netaddr.new('fe80::221:63f:fe75:aa17/64');
 * addr6.add(256);          // "fe80::221:63f:fe75:ab17/64"
 *
 * const mac = netaddr.new('00:14:22:01:23:45');
 * mac.add(256);            // "00:14:22:01:24:45"
 */
static uc_value_t *
uc_netaddr_range_add(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_range_add_sub(vm, nargs, true);
}

/**
 * Subtract the given amount from this CIDR instance. If the result would
 * underflow the lowest possible address, the result is set to the lowest
 * possible address.
 *
 * @function module:netaddr.range#sub
 *
 * @param {number|string|module:netaddr.range} amount
 * A numeric value, an `netaddr.range` instance or a string convertible by
 * `new()`.
 *
 * @param {boolean} [inplace]
 * If `true`, modify this instance instead of returning a new derived CIDR
 * instance.
 *
 * @returns {module:netaddr.range|boolean|null}
 * When subtracting inplace: `true` if the subtraction succeeded or
 * `false` when the subtraction underflowed. When deriving a new CIDR: a
 * new instance representing the value of this instance minus the
 * subtracted amount or the lowest address if the subtraction underflowed.
 * Returns `null` if the amount argument is not convertible.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1/24');
 * addr.sub(256);         // "192.168.0.1/24"
 * addr.sub('0.168.0.0'); // "192.0.1.1/24"
 *
 * addr.sub(256, true);   // true
 * addr;                  // "192.168.0.1/24"
 *
 * addr.sub('255.0.0.0', true);  // false (underflow)
 * addr;                         // "0.0.0.0/24"
 *
 * const addr6 = netaddr.new('fe80::221:63f:fe75:aa17/64');
 * addr6.sub(256);         // "fe80::221:63f:fe75:aa17/64"
 *
 * const mac = netaddr.new('00:14:22:01:23:45');
 * mac.sub(256);           // "00:14:22:01:22:45"
 */
static uc_value_t *
uc_netaddr_range_sub(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_range_add_sub(vm, nargs, false);
}

/**
 * Derive the lowest usable host address of this CIDR instance.
 *
 * For IPv4 ranges this is the network address plus one, except for
 * point-to-point `/31` ranges where the network address itself is the
 * first usable host; for IPv6 ranges the lowest address in the range
 * (the "network" address); for host addresses and MAC addresses the
 * address itself.
 *
 * @function module:netaddr.range#minhost
 *
 * @returns {module:netaddr.range} A new CIDR instance representing the lowest
 * usable host address of this instance
 *
 * @example
 * const range = netaddr.new('172.19.37.45/16');
 * range.minhost();  // "172.19.0.1"
 */
static uc_value_t *
uc_netaddr_range_minhost(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t r = *p1;
	uint8_t i, rest, carry;

	apply_mask(&r, r.bits, false);

	/*
	 * skip the network address for IPv4 ranges, except for /31
	 * point-to-point ranges where the network address itself is the
	 * first usable host
	 */
	if (r.family == AF_INET &&
	    r.bits < AF_BITS(AF_INET) && r.bits != 31) {
		r.bits = AF_BITS(AF_INET);
		r.addr.v4.s_addr = htonl(ntohl(r.addr.v4.s_addr) + 1);
	}
	else if (r.family == AF_INET && r.bits == 31) {
		r.bits = AF_BITS(AF_INET);
	}
	else if (r.bits < AF_BITS(r.family)) {
		r.bits = AF_BITS(r.family);

		for (i = 0, carry = 1; i < AF_BYTES(r.family); i++) {
			rest = (BYTE(&r, i) + carry) > 255;
			BYTE(&r, i) += carry;
			carry = rest;
		}
	}

	return new_range(vm, &r);
}

/**
 * Derive the highest usable host address of this CIDR instance.
 *
 * For IPv4 ranges this is the broadcast address minus one, except for
 * point-to-point `/31` ranges where the broadcast address itself is the
 * last usable host; for IPv6 ranges the highest address in the range
 * (the "broadcast" address); for host addresses and MAC addresses the
 * address itself.
 *
 * @function module:netaddr.range#maxhost
 *
 * @returns {module:netaddr.range} A new CIDR instance representing the highest
 * usable host address of this instance
 *
 * @example
 * const range = netaddr.new('172.19.37.45/16');
 * range.maxhost();  // "172.19.255.254"
 */
static uc_value_t *
uc_netaddr_range_maxhost(uc_vm_t *vm, size_t nargs)
{
	range_t *p1 = get_this_range(vm);
	range_t r = *p1;

	apply_mask(&r, r.bits, true);

	/*
	 * skip the broadcast address for IPv4 ranges, except for /31
	 * point-to-point ranges where the broadcast address itself is the
	 * last usable host
	 */
	if (r.family == AF_INET &&
	    r.bits < AF_BITS(AF_INET) && r.bits != 31) {
		r.bits = AF_BITS(AF_INET);
		r.addr.v4.s_addr = htonl(ntohl(r.addr.v4.s_addr) - 1);
	}
	else if (r.family == AF_INET && r.bits == 31) {
		r.bits = AF_BITS(AF_INET);
	}
	else {
		r.bits = AF_BITS(r.family);
	}

	return new_range(vm, &r);
}

/**
 * Get the string representation of this CIDR instance.
 *
 * @function module:netaddr.range#string
 *
 * @returns {string} A string representation of this CIDR
 *
 * @example
 * const addr = netaddr.new('172.19.37.45/16');
 * addr.string();  // "172.19.37.45/16"
 */
static uc_value_t *
uc_netaddr_range_string(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);

	return format_range(vm, p);
}

/**
 * Get the string representation of this CIDR instance.
 *
 * This method is invoked by `print()` and string interpolation to render
 * the instance, see {@link module:netaddr.range#string|string()}.
 *
 * @function module:netaddr.range#tostring
 *
 * @returns {string} A string representation of this CIDR
 *
 * @example
 * const addr = netaddr.new('172.19.37.45/16');
 *
 * print(addr);   // "172.19.37.45/16"
 * `${addr}`;     // "172.19.37.45/16"
 */
static uc_value_t *
uc_netaddr_range_tostring(uc_vm_t *vm, size_t nargs)
{
	return uc_netaddr_range_string(vm, nargs);
}

/*
 * range property access (__get__ / __set__ metamethods)
 */

static int64_t
key_to_index(uc_value_t *key)
{
	const char *k;
	int64_t idx;
	double d;
	char *e;

	if (ucv_type(key) == UC_DOUBLE) {
		d = ucv_double_get(key);

		if (trunc(d) != d)
			return INT64_MIN;

		return (int64_t)d;
	}
	else if (ucv_type(key) == UC_INTEGER) {
		return ucv_int64_get(key);
	}
	else if (ucv_type(key) == UC_STRING) {
		errno = 0;
		k = ucv_string_get(key);
		idx = strtoll(k, &e, 0);

		if (errno != 0 || e == k || *e != 0)
			return INT64_MIN;

		return idx;
	}

	return INT64_MIN;
}

static int64_t
get_range_byte_index(range_t *p, uc_value_t *key)
{
	int64_t idx = key_to_index(key);
	int64_t len = AF_BYTES(p->family);

	if (idx == INT64_MIN)
		return INT64_MIN;

	if (idx < 0)
		idx += len;

	if (idx < 0 || idx >= len)
		return INT64_MIN;

	return idx;
}

/**
 * Property access for `netaddr.range` instances.
 *
 * Invoked by the interpreter for property reads which do not match a
 * method of this type, e.g. `addr[0]`, `addr.bits` or `addr.netmask`.
 *
 * The following keys are supported:
 *
 * | Key | Description |
 * | --- | --- |
 * | `0 .. n-1` | The individual address bytes, negative indices count from the end |
 * | `bits` | The prefix size in bits |
 * | `family` | The address family (`AF_INET`, `AF_INET6` or `AF_PACKET`) |
 * | `scope` | The address scope (numeric interface index) for IPv6 and MAC instances |
 * | `scopeid` | The address scope as an interface name (or `null` if not set) |
 * | `netmask` | The netmask as a string, e.g. `"255.255.255.0"` |
 * | `host` | The host address as a new range (full-width prefix) |
 * | `mapped4` | The mapped IPv4 address as a new range (or `null` if not a mapped IPv4) |
 * | `unscopename` | The interface name of the address scope (or an empty string) |
 * | `size` | The number of addresses in this range (or `null` if too large) |
 *
 * @function module:netaddr.range#__get__
 *
 * @param {number|string} key
 * The property key to read.
 *
 * @returns {number|string|null}
 *
 * @example
 * const addr = netaddr.new('192.168.1.1/24');
 *
 * addr[0];       // 192
 * addr[-1];      // 1
 * addr.bits;     // 24
 * addr.family;   // 2
 * addr.netmask;  // "255.255.255.0"
 * addr.host;     // netaddr.range "192.168.1.1" (full-width prefix)
 * addr.size;     // 256
 */
static uc_value_t *
uc_netaddr_range_get(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	uc_value_t *key = uc_fn_arg(0);
	int64_t idx;

	if (ucv_type(key) == UC_INTEGER || ucv_type(key) == UC_DOUBLE) {
		idx = get_range_byte_index(p, key);

		return (idx == INT64_MIN) ? NULL
		                          : ucv_int64_new(p->addr.u8[idx]);
	}

	if (ucv_type(key) == UC_STRING) {
		const char *k = ucv_string_get(key);

		if (!strcmp(k, "bits"))
			return ucv_int64_new(p->bits);

		if (!strcmp(k, "family")) {
			switch (p->family) {
			case AF_INET:
				return ucv_int64_new(4);

			case AF_INET6:
				return ucv_int64_new(6);

			default:
				return ucv_int64_new(1);
			}
		}

		if (!strcmp(k, "scope"))
			return ucv_int64_new(p->scope);

		if (!strcmp(k, "scopeid")) {
			char ifname[IF_NAMESIZE];

			if ((p->family == AF_INET6 || p->family == AF_PACKET) &&
			    p->scope != 0 &&
			    if_indextoname(p->scope, ifname) != NULL)
				return ucv_string_new(ifname);

			return NULL;
		}

		if (!strcmp(k, "netmask")) {
			range_t m = { };

			m.scope = 0;
			m.bits = AF_BITS(p->family);
			m.family = p->family;

			memset(&m.addr.v6.s6_addr, 0xFF, sizeof(m.addr.v6.s6_addr));
			apply_mask(&m, p->bits, false);

			return format_range(vm, &m);
		}

		if (!strcmp(k, "host")) {
			range_t h = *p;

			h.bits = AF_BITS(p->family);

			return new_range(vm, &h);
		}

		if (!strcmp(k, "mapped4")) {
			if (!is_mapped4(p))
				return NULL;

			range_t m = { };

			m.scope = 0;
			m.family = AF_INET;
			m.bits = (p->bits > AF_BITS(AF_INET)) ? AF_BITS(AF_INET) : p->bits;
			memcpy(&m.addr.v4, p->addr.v6.s6_addr + 12, sizeof(m.addr.v4));

			return new_range(vm, &m);
		}

		if (!strcmp(k, "unscopename")) {
			char ifname[IF_NAMESIZE];

			if (p->family == AF_INET || p->scope == 0 ||
			    if_indextoname(p->scope, ifname) == NULL)
				return ucv_string_new("");

			return ucv_string_new(ifname);
		}

		if (!strcmp(k, "size")) {
			int rest = AF_BITS(p->family) - p->bits;

			/* 2^63 does not fit into a signed 64 bit integer */
			if (rest < 0 || rest >= 63)
				return NULL;

			return ucv_int64_new(1LL << rest);
		}
	}

	return NULL;
}

/**
 * Property assignment for `netaddr.range` instances.
 *
 * Invoked by the interpreter for property writes, e.g. `addr[0] = 10` or
 * `addr.bits = 16`.
 *
 * The following keys are supported:
 *
 * - Numeric keys write the individual address bytes (value range `0..255`,
 *   negative indices count from the end of the address).
 * - The `bits` key sets the prefix size in bits (`0..32` for IPv4,
 *   `0..128` for IPv6, `0..48` for MAC addresses).
 * - The `scope` key sets the address scope (numeric interface index)
 *   for IPv6 and MAC address instances.
 * - The `scopeid` key sets the address scope to the given interface
 *   name or numeric index for IPv6 and MAC address instances.
 * - The `host`, `mapped4`, `unscopename` and `size` keys are read-only
 *   computed properties; writes to them are silently ignored.
 *
 * Writes to other keys or with invalid values are silently ignored.
 *
 * @function module:netaddr.range#__set__
 *
 * @param {number|string} key
 * The property key to write.
 *
 * @param {number} value
 * The value to assign.
 *
 * @returns {null} Always returns `null`, the return value is discarded by
 * the interpreter.
 *
 * @example
 * const addr = netaddr.new('192.168.1.1/24');
 *
 * addr[3] = 10;     // "192.168.1.10/24"
 * addr[-1] = 10;    // "192.168.1.10/24"
 * addr.bits = 16;   // "192.168.1.10/16"
 */
static uc_value_t *
uc_netaddr_range_set(uc_vm_t *vm, size_t nargs)
{
	range_t *p = get_this_range(vm);
	uc_value_t *key = uc_fn_arg(0);
	uc_value_t *val = uc_fn_arg(1);
	int64_t idx;
	uint64_t n;

	if (ucv_type(key) == UC_INTEGER || ucv_type(key) == UC_DOUBLE) {
		if (ucv_type(val) != UC_INTEGER && ucv_type(val) != UC_DOUBLE)
			return NULL;

		idx = get_range_byte_index(p, key);

		if (idx == INT64_MIN)
			return NULL;

		n = ucv_to_unsigned(val);

		if (errno == 0 && n <= 0xFF)
			p->addr.u8[idx] = (uint8_t)n;
	}
	else if (ucv_type(key) == UC_STRING) {
		const char *k = ucv_string_get(key);

		if (!strcmp(k, "bits")) {
			int16_t bits;

			if (check_bits(vm, val, p, &bits))
				p->bits = bits;
		}
		else if (!strcmp(k, "scope")) {
			if ((p->family == AF_INET6 || p->family == AF_PACKET) &&
			    (ucv_type(val) == UC_INTEGER || ucv_type(val) == UC_DOUBLE)) {
				n = ucv_to_unsigned(val);

				if (errno == 0 && n <= UINT32_MAX)
					p->scope = (uint32_t)n;
			}
		}
		else if (!strcmp(k, "scopeid")) {
			if (p->family == AF_INET6 || p->family == AF_PACKET) {
				uint32_t idx = parse_scope(vm, val, p, false);

				if (idx != (uint32_t)-1)
					p->scope = idx;
			}
		}
		/*
		 * host, mapped4, unscopename and size are read-only computed
		 * properties, writes to them are silently ignored
		 */
	}

	return NULL;
}

static const uc_function_list_t range_fns[] = {
	{ "is4", uc_netaddr_range_is4 },
	{ "is4rfc1918", uc_netaddr_range_is4rfc1918 },
	{ "is4linklocal", uc_netaddr_range_is4linklocal },
	{ "is6", uc_netaddr_range_is6 },
	{ "is6linklocal", uc_netaddr_range_is6linklocal },
	{ "is6mapped4", uc_netaddr_range_is6mapped4 },
	{ "ismac", uc_netaddr_range_ismac },
	{ "ismaclocal", uc_netaddr_range_ismaclocal },
	{ "ismacmcast", uc_netaddr_range_ismacmcast },
	{ "lower", uc_netaddr_range_lower },
	{ "higher", uc_netaddr_range_higher },
	{ "equal", uc_netaddr_range_equal },
	{ "prefix", uc_netaddr_range_prefix },
	{ "network", uc_netaddr_range_network },
	{ "mask", uc_netaddr_range_mask },
	{ "broadcast", uc_netaddr_range_broadcast },
	{ "scoped", uc_netaddr_range_scoped },
	{ "unscoped", uc_netaddr_range_unscoped },
	{ "tomac", uc_netaddr_range_tomac },
	{ "tolinklocal", uc_netaddr_range_tolinklocal },
	{ "contains", uc_netaddr_range_contains },
	{ "add", uc_netaddr_range_add },
	{ "sub", uc_netaddr_range_sub },
	{ "minhost", uc_netaddr_range_minhost },
	{ "maxhost", uc_netaddr_range_maxhost },
	{ "string", uc_netaddr_range_string },
	{ "tostring", uc_netaddr_range_tostring },
	{ "__get__", uc_netaddr_range_get },
	{ "__set__", uc_netaddr_range_set },
};

static const uc_function_list_t ip_fns[] = {
	{ "new", uc_netaddr_new },
	{ "v4", uc_netaddr_v4 },
	{ "v6", uc_netaddr_v6 },
	{ "mac", uc_netaddr_mac },
	{ "checkv4", uc_netaddr_checkv4 },
	{ "checkv6", uc_netaddr_checkv6 },
	{ "checkmac", uc_netaddr_checkmac },
};

void
uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_type_declare(vm, range_type, range_fns, free);
	uc_function_list_register(scope, ip_fns);
}
