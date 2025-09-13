// Nat64 jargons
//COMPLETE LOGIC

/*int
npf_extract_ipv4(const npf_cache_t *npc, u_int which,
    const npf_addr_t *pref, npf_netmask_t len,
    npf_addr_t *result_ipv4addr)
{
    npf_addr_t *ipv6_dest;
    uint8_t temp[16];        // Temporary buffer for modified IPv6
    uint8_t *adjusted;
    npf_addr_t new_ipv4;
    unsigned offset;

    KASSERT(which == NPF_SRC || which == NPF_DST);

    if (!npf_iscached(npc, NPC_IP6)) {
        return EINVAL;
    }

   ipv6_dest = npc->npc_ips[NPF_DST];

    memset(&new_ipv4, 0, sizeof(npf_addr_t));
    memset(temp, 0, sizeof(temp));

    // Must be byte-aligned and <= 96
    if (len % 8 != 0 || len > 96) {
        return EINVAL;
    }

    offset = len / 8;
    adjusted = temp;

    switch (len) {
    case 96:
        // Standard NAT64 case: last 4 bytes are the IPv4
        memcpy(&new_ipv4, ((const uint8_t)ipv6_dest) + 12, 4);
        break;

    case 32:
    case 40:
    case 48:
    case 56:
    case 64:
        // Step 1: copy original IPv6 to temp variable
        memcpy(temp, ipv6_dest, 16);

        // Step 2: remove the 'u' byte at index 8
		//by shifting bytes 9–15 left
		// according to RFC 6052
        memmove(&temp[8], &temp[9], 7);  // Now 15-byte adjusted address

        // Step 3: extract 4 bytes from new offset
		adjusted = temp;
        memcpy(&new_ipv4, adjusted + offset, 4);
        break;

    default:
        return EINVAL;
    }

    *result_ipv4addr = new_ipv4;
    return 0;
}





// IGNORE PLEASE
// Handles only /96 logic
// incomplete logic

int npf_siit64_rwr(
    const npf_cache_t *npc,          // Parsed packet metadata (headers, addresses)
    u_int which,                     // Either NPF_SRC or NPF_DST — tells us which IP to translate
    //const npf_addr_t *ipv6addr,        // The full IPv6 address to be translated
    const npf_addr_t *pref,        // The NAT64 prefix (e.g., 64:ff9b::/96)
    npf_netmask_t len,               // Prefix length (e.g., 96)
    npf_addr_t *result_ipv4addr        // Output buffer for translated IPv4 address
){

	// Extract the address from cache (like in nat66)
    //npf_addr_t *ipv6addr = npc->npc_ips[which];
	npf_addr_t *ipv6_dest = npc->npc_ips[NPF_DST];

	//Do not use word/byte pointer it causes alignment issues in the stack.
    //const uint8_t *ipv6 = ipv6addr->word8;
    //uint8_t *ipv4 = result_ipv4addr->word8;
	//destination ipv4 address
	npf_addr_t new_ipv4;
    unsigned offset;

	KASSERT(which == NPF_SRC || which == NPF_DST);

	 if (!npf_iscached(npc, NPC_IP6)) {
        return EINVAL;
    }

    // Determine the offset based on prefix length (RFC 6052)
    switch (len) {
    case 32: offset = 4; break;
    case 40: offset = 5; break;
    case 48: offset = 6; break;
    case 56: offset = 7; break;
    case 64: offset = 8; break;
    case 96: offset = 12; break;
    default:
        return EINVAL;
    }

	// Clear the output address
    memset(&new_ipv4, 0, sizeof(npf_addr_t));

    // Copy IPv4 bytes from inside IPv6 address (based on offset)
    memcpy(&new_ipv4, ((const uint8_t *)ipv6_dest) + offset, 4);

    // Store in result in the output params
    *result_ipv4addr = new_ipv4;


    //The last 4 bytes (embedded IPv4 address) from IPv6 is
	// copied into result buffer
	//memcpy(result_ipv4addr, ((const uint8_t *)ipv6addr) + offset, 4);
	// The rest could contain garbage if not zeroed
    //memset(((uint8_t *)result_ipv4addr) + 4, 0, sizeof(npf_addr_t) - 4);
    //memcpy(ipv4, &ipv6[offset], 4);

    return 0;
}
*/

//UPDATED EXTRACT IPV4 FROM IPV6 ADDRESS
// COVERS ALL PREFIX LENGTH BASED ON 6052
/*
int npf_siit64_rwr(
    const npf_cache_t *npc,
    u_int which,
    const npf_addr_t *pref,
    npf_netmask_t len,
    npf_addr_t *result_ipv4addr
){
    const uint8_t *ipv6_bytes;
    uint8_t temp[16]; // Temporary buffer for adjusted address
    uint8_t *adjusted;
    npf_addr_t new_ipv4;
    unsigned prefix_bytes;

    KASSERT(which == NPF_SRC || which == NPF_DST);

    if (!npf_iscached(npc, NPC_IP6)) {
        return EINVAL;
    }

    ipv6_bytes = (const uint8_t *)npc->npc_ips[which];

    // Clear everything
    memset(&new_ipv4, 0, sizeof(npf_addr_t));
    memset(temp, 0, sizeof(temp));

    // Convert prefix length from bits to bytes
    if (len % 8 != 0 || len > 96) {
        return EINVAL; // Only support byte-aligned and <= 96 prefixes
    }
    prefix_bytes = len / 8;

    if (len == 96) {
        // Standard case: last 4 bytes are IPv4
        memcpy(&new_ipv4, ipv6_bytes + 12, 4);
    } else {
        // RFC 6052: must remove 'u' byte at byte 8 and shift
        // Step 1: copy IPv6 address into temp
        memcpy(temp, ipv6_bytes, 16);

        // Step 2: remove "u" byte by shifting bytes 9..15 left by 1
        memmove(&temp[8], &temp[9], 7);  // bytes [9] to [15] -> [8] to [14]

        // Step 3: adjusted address is now 15 bytes, get IPv4 starting at prefix
        adjusted = temp;
        memcpy(&new_ipv4, adjusted + prefix_bytes, 4);
    }

    *result_ipv4addr = new_ipv4;
    return 0;
}


int npf_siit64_rwr(
    const npf_cache_t *npc,          // Parsed packet metadata (headers, addresses)
    u_int which,                     // Either NPF_SRC or NPF_DST — tells us which IP to translate
    //const npf_addr_t *ipv6addr,        // The full IPv6 address to be translated
    const npf_addr_t *pref,        // The NAT64 prefix (e.g., 64:ff9b::/96)
    npf_netmask_t len,               // Prefix length (e.g., 96)
    npf_addr_t *result_ipv4addr        // Output buffer for translated IPv4 address
){

	// Extract the address from cache (like in nat66)
    //npf_addr_t *ipv6addr = npc->npc_ips[which];
	npf_addr_t *ipv6_dest = npc->npc_ips[NPF_DST];
	//destination ipv4 address
	npf_addr_t new_ipv4;

	//Do not use word/byte pointer it causes alignment issues in the stack.
    //const uint8_t *ipv6 = ipv6addr->word8;
    //uint8_t *ipv4 = result_ipv4addr->word8;
    unsigned offset;

	KASSERT(which == NPF_SRC || which == NPF_DST);

	 if (!npf_iscached(npc, NPC_IP6)) {
        return EINVAL;
    }

    // Determine the offset based on prefix length (RFC 6052)
    switch (len) {
    case 32: offset = 4; break;
    case 40: offset = 5; break;
    case 48: offset = 6; break;
    case 56: offset = 7; break;
    case 64: offset = 8; break;
    case 96: offset = 12; break;
    default:
        return EINVAL;
    }

	// Clear the output address
    memset(&new_ipv4, 0, sizeof(npf_addr_t));

    // Copy IPv4 bytes from inside IPv6 address (based on offset)
    memcpy(&new_ipv4, ((const uint8_t *)ipv6_dest) + offset, 4);

    // Store in result in the output params
    *result_ipv4addr = new_ipv4;


    //The last 4 bytes (embedded IPv4 address) from IPv6 is
	// copied into result buffer
	//memcpy(result_ipv4addr, ((const uint8_t *)ipv6addr) + offset, 4);
	// The rest could contain garbage if not zeroed
    //memset(((uint8_t *)result_ipv4addr) + 4, 0, sizeof(npf_addr_t) - 4);
    //memcpy(ipv4, &ipv6[offset], 4);

    return 0;
}
*/

/* error code */
/*
int npf_nat64_rwrheader(npf_cache_t *npc, nbuf_t **nbuf,
    const npf_addr_t *src, const npf_addr_t *dst)
{
	struct mbuf *m = *nbuf;
	struct ip *ip4;
	struct ip6_hdr *ip6;
	size_t hlen;

	// Strip the existing IP header based on cached header length.
	m_adj(m, npc->npc_hlen);

	// Determine the size of the new header to prepend.
	switch (npc->npc_info) {
	case NPC_IP6:
		hlen = sizeof(struct ip);        //  IPv6 -> IPv4 translation 
		break;
	case NPC_IP4:
		hlen = sizeof(struct ip6_hdr);   // IPv4 -> IPv6 translation 
		break;
	default:
		return EINVAL;
	}

	// Prepend space for the new IP header.
	m = m_prepend(m, hlen, M_DONTWAIT);
	if (m == NULL) {
		return ENOMEM;
	}
	*nbuf = m;

	// Perform the translation depending on original address family.
	switch (npc->npc_info) {
	case NPC_IP6: {
		// IPv6 → IPv4 
		const struct ip6_hdr *oip6 = npc->npc_ip.v6;
		ip4 = mtod(m, struct ip *);
		memset(ip4, 0, sizeof(struct ip));

		ip4->ip_v     = IPVERSION;
		ip4->ip_hl    = sizeof(struct ip) >> 2;
		ip4->ip_tos   = 0;
		ip4->ip_len   = htons(hlen + ntohs(oip6->ip6_plen));
		ip4->ip_id    = htons(0)
		ip4->ip_off   = htons(IP_DF);
		ip4->ip_ttl   = oip6->ip6_hlim;
		ip4->ip_p     = npc->npc_next_proto;
		ip4->ip_src.s_addr = src->s6_addr32[0];
		ip4->ip_dst.s_addr = dst->s6_addr32[0];
		break;
	}
		//version 1
	case NPC_IP4: {
		// IPv4 → IPv6
		const struct ip *oip4 = npc->npc_ip.v4;
		ip6 = mtod(m, struct ip6_hdr *);
		memset(ip6, 0, sizeof(struct ip6_hdr));

		ip6->ip6_vfc  = IPV6_VERSION;
		ip6->ip6_nxt  = npc->npc_next_proto;
		ip6->ip6_hlim = (oip4->ip_ttl < IPV6_DEFHLIM) ? oip4->ip_ttl : IPV6_DEFHLIM;

		uint16_t payload_len = ntohs(oip4->ip_len) - (oip4->ip_hl << 2);
		ip6->ip6_plen = htons(payload_len);

		memcpy(&ip6->ip6_src, src, sizeof(struct in6_addr));
		memcpy(&ip6->ip6_dst, dst, sizeof(struct in6_addr));
		break;

		//version 2

		case NPC_IP4: {
		// IPv4 -> IPv6 
		const struct ip *oip4 = npc->npc_ip.v4;
		ip6 = mtod(m, struct ip6_hdr *);
		memset(ip6, 0, sizeof(struct ip6_hdr));

		ip6->ip6_vfc  = IPV6_VERSION;
		ip6->ip6_nxt  = npc->npc_next_proto;
		ip6->ip6_hlim = (oip4->ip_ttl < IPV6_DEFHLIM) ? oip4->ip_ttl : IPV6_DEFHLIM;

		uint16_t payload_len = ntohs(oip4->ip_len) - (oip4->ip_hl << 2);
		ip6->ip6_plen = htons(payload_len);

		memcpy(&ip6->ip6_src, src, sizeof(struct in6_addr));
		memcpy(&ip6->ip6_dst, dst, sizeof(struct in6_addr));
		break;
	}
	}
	default:
		return EINVAL;
	}

	return 0;
}
*/