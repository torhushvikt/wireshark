/* packet-ipv8.c
 * Routines for IPv8 packet disassembly
 *
 * Wireshark - Network traffic analyzer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/in_cksum.h>
#include <epan/tfs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>

#include "packet-ip.h"

void proto_register_ipv8(void);
void proto_reg_handoff_ipv8(void);

#define IPV8_HLEN_MIN 28

static int proto_ipv8;

static int hf_ipv8_version;
static int hf_ipv8_hdr_len;
static int hf_ipv8_dsfield;
static int hf_ipv8_len;
static int hf_ipv8_id;
static int hf_ipv8_flags;
static int hf_ipv8_flags_rb;
static int hf_ipv8_flags_df;
static int hf_ipv8_flags_mf;
static int hf_ipv8_frag_offset;
static int hf_ipv8_ttl;
static int hf_ipv8_proto;
static int hf_ipv8_checksum;
static int hf_ipv8_checksum_calculated;
static int hf_ipv8_checksum_status;
static int hf_ipv8_src_asn;
static int hf_ipv8_src_host;
static int hf_ipv8_dst_asn;
static int hf_ipv8_dst_host;
static int hf_ipv8_src;
static int hf_ipv8_dst;
static int hf_ipv8_addr;
static int hf_ipv8_options;
static int hf_ipv8_reassembled_in;
static int hf_ipv8_reassembled_length;
static int hf_ipv8_reassembled_data;

static int ett_ipv8;
static int ett_ipv8_flags;
static int ett_ipv8_options;

static expert_field ei_ipv8_bogus_version;
static expert_field ei_ipv8_bogus_header_length;
static expert_field ei_ipv8_bogus_length;
static expert_field ei_ipv8_checksum_bad;

/* Reassembly table */
static reassembly_table ipv8_reassembly_table;

/* Track conversation IDs */
static bool ipv8_track_conv_id = true;

/* Preference for fragmentation reassembly */
static bool ipv8_defragment = true;

static const true_false_string flags_set_notset = {
    "Set",
    "Not set"
};

static void
format_ipv8_addr(tvbuff_t *tvb, int asn_offset, int host_offset, wmem_allocator_t *scope, char **out)
{
    const char *asn;
    const char *host;

    asn = tvb_ip_to_str(scope, tvb, asn_offset);
    host = tvb_ip_to_str(scope, tvb, host_offset);
    *out = ws_strdup_printf("%s.%s", asn, host);
}

/* Conversation data structure for IPv8 */
typedef struct {
    uint32_t stream;
} ipv8_conversation_t;

static ipv8_conversation_t *
get_ipv8_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    ipv8_conversation_t *ipv8d;

    ipv8d = (ipv8_conversation_t *)conversation_get_proto_data(conv, proto_ipv8);
    if (!ipv8d) {
        ipv8d = wmem_new(wmem_file_scope(), ipv8_conversation_t);
        ipv8d->stream = 0;
        conversation_add_proto_data(conv, proto_ipv8, ipv8d);
    }
    return ipv8d;
}

/* Fragment reassembly info */
static const reassembly_table_functions addresses_reassembly_table_functions = {
    .hash_func = reassembly_table_hash_addresses,
    .cmp_func = cmp_address,
    .key_free_func = reassembly_table_addresses_key_free
};

static dissector_handle_t ipv8_handle;

/* Dissect IPv8 options field (similar to IPv4 options) */
static void
dissect_ipv8_options(tvbuff_t *tvb, int offset, unsigned opt_len, packet_info *pinfo, proto_tree *opt_tree)
{
    unsigned remaining = opt_len;
    int opt_offset = offset;
    
    if (opt_len == 0) {
        return;
    }

    while (remaining > 0) {
        uint8_t opt_type;
        uint8_t opt_copy;
        uint8_t opt_class;
        uint8_t opt_number;
        uint8_t opt_data_len;
        
        opt_type = tvb_get_uint8(tvb, opt_offset);
        opt_copy = opt_type >> 7;
        opt_class = (opt_type >> 5) & 0x3;
        opt_number = opt_type & 0x1f;
        
        /* Handle End of Option List (0) and NOP (1) */
        if (opt_type == 0) {
            /* End of Option List */
            proto_tree_add_item(opt_tree, hf_ipv8_options, tvb, opt_offset, 1, ENC_NA);
            break;
        }
        if (opt_type == 1) {
            /* No Operation */
            proto_tree_add_item(opt_tree, hf_ipv8_options, tvb, opt_offset, 1, ENC_NA);
            opt_offset++;
            remaining--;
            continue;
        }

        /* Option with length field */
        if (remaining < 2) {
            /* Not enough data for length field */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ipv8_bogus_length,
                tvb, opt_offset, remaining,
                "Option length field extends past end of options");
            break;
        }

        opt_data_len = tvb_get_uint8(tvb, opt_offset + 1);

        if (opt_data_len < 2) {
            /* Option data length too short */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ipv8_bogus_length,
                tvb, opt_offset, 2,
                "IPv8 option length too short: %u (must be >= 2)", opt_data_len);
            break;
        }

        if (opt_data_len > remaining) {
            /* Option extends past end */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ipv8_bogus_length,
                tvb, opt_offset, remaining,
                "IPv8 option (type %u) length %u extends past end of options (remaining: %u)",
                opt_type, opt_data_len, remaining);
            break;
        }

        /* Add the option to tree */
        proto_tree_add_item(opt_tree, hf_ipv8_options, tvb, opt_offset, opt_data_len, ENC_NA);

        opt_offset += opt_data_len;
        remaining -= opt_data_len;
    }
}

static int
dissect_ipv8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *ip_tree;
    proto_item *tf;
    uint8_t version;
    uint8_t ihl;
    unsigned hlen;
    uint32_t total_len;
    uint16_t frag_off;
    uint16_t checksum;
    uint16_t ipsum;
    uint8_t proto;
    int payload_offset;
    tvbuff_t *next_tvb;
    ws_ip8 *iph;
    fragment_head *ipv8fd_head = NULL;
    bool update_col_info = true;
    bool save_fragmented;
    address src64, dst64;
    proto_item *item = NULL;
    conversation_t *conv;
    ipv8_conversation_t *ipv8d;
    static uint32_t ipv8_stream_count = 0;
    
    static int *const flags_fields[] = {
        &hf_ipv8_flags_rb,
        &hf_ipv8_flags_df,
        &hf_ipv8_flags_mf,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv8");
    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_bits8(tvb, 0, 4);
    ihl = tvb_get_bits8(tvb, 4, 4);
    hlen = ihl * 4;

    ti = proto_tree_add_item(tree, proto_ipv8, tvb, 0,
        MIN(tvb_captured_length(tvb), (int)(hlen >= IPV8_HLEN_MIN ? hlen : IPV8_HLEN_MIN)), ENC_NA);
    ip_tree = proto_item_add_subtree(ti, ett_ipv8);

    tf = proto_tree_add_bits_item(ip_tree, hf_ipv8_version, tvb, 0, 4, ENC_NA);
    if (version != 8) {
        expert_add_info(pinfo, tf, &ei_ipv8_bogus_version);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IPv8 version (%u)", version);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_uint_bits_format_value(ip_tree, hf_ipv8_hdr_len, tvb, 4, 4, hlen,
        ENC_BIG_ENDIAN, "%u bytes (%u)", hlen, ihl);

    if (hlen < IPV8_HLEN_MIN) {
        expert_add_info_format(pinfo, tf, &ei_ipv8_bogus_header_length,
            "Bogus IPv8 header length (%u, must be at least %u)", hlen, IPV8_HLEN_MIN);
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "Bogus IPv8 header length (%u, must be at least %u)", hlen, IPV8_HLEN_MIN);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(ip_tree, hf_ipv8_dsfield, tvb, 1, 1, ENC_NA);

    total_len = tvb_get_ntohs(tvb, 2);
    proto_tree_add_uint(ip_tree, hf_ipv8_len, tvb, 2, 2, total_len);
    if (total_len < hlen) {
        expert_add_info(pinfo, tf, &ei_ipv8_bogus_length);
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "Bogus IPv8 length (%u, less than header length %u)", total_len, hlen);
        return tvb_captured_length(tvb);
    }
    if (total_len <= tvb_reported_length(tvb)) {
        set_actual_length(tvb, total_len);
    }

    proto_tree_add_item(ip_tree, hf_ipv8_id, tvb, 4, 2, ENC_BIG_ENDIAN);

    frag_off = tvb_get_ntohs(tvb, 6);
    proto_tree_add_bitmask_with_flags(ip_tree, tvb, 6, hf_ipv8_flags,
        ett_ipv8_flags, flags_fields, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    proto_tree_add_uint_format_value(ip_tree, hf_ipv8_frag_offset, tvb, 6, 2,
        frag_off, "%u", (frag_off & IP_OFFSET) * 8);

    proto_tree_add_item(ip_tree, hf_ipv8_ttl, tvb, 8, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint8(ip_tree, hf_ipv8_proto, tvb, 9, 1, ENC_BIG_ENDIAN, &proto);

    checksum = tvb_get_ntohs(tvb, 10);
    if (tvb_bytes_exist(tvb, 0, hlen)) {
        ipsum = ip_checksum_tvb(tvb, 0, hlen);
        proto_tree_add_checksum(ip_tree, tvb, 10, hf_ipv8_checksum, hf_ipv8_checksum_status,
            &ei_ipv8_checksum_bad, pinfo, ipsum, ENC_BIG_ENDIAN,
            PROTO_CHECKSUM_VERIFY | PROTO_CHECKSUM_IN_CKSUM);
        if (ipsum == 0) {
            tf = proto_tree_add_uint(ip_tree, hf_ipv8_checksum_calculated, tvb, 10, 2, checksum);
        } else {
            tf = proto_tree_add_uint(ip_tree, hf_ipv8_checksum_calculated, tvb, 10, 2,
                in_cksum_shouldbe(checksum, ipsum));
        }
        proto_item_set_generated(tf);
    } else {
        proto_tree_add_item(ip_tree, hf_ipv8_checksum, tvb, 10, 2, ENC_BIG_ENDIAN);
        tf = proto_tree_add_uint(ip_tree, hf_ipv8_checksum_status, tvb, 10, 0, PROTO_CHECKSUM_E_UNVERIFIED);
        proto_item_set_generated(tf);
    }

    proto_tree_add_item(ip_tree, hf_ipv8_src_asn, tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ip_tree, hf_ipv8_src_host, tvb, 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ip_tree, hf_ipv8_dst_asn, tvb, 20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ip_tree, hf_ipv8_dst_host, tvb, 24, 4, ENC_BIG_ENDIAN);

    if (tree) {
        char *src_full;
        char *dst_full;
        proto_item *tmp;

        format_ipv8_addr(tvb, 12, 16, pinfo->pool, &src_full);
        format_ipv8_addr(tvb, 20, 24, pinfo->pool, &dst_full);

        tmp = proto_tree_add_string(ip_tree, hf_ipv8_src, tvb, 12, 8, src_full);
        proto_item_set_generated(tmp);

        tmp = proto_tree_add_string(ip_tree, hf_ipv8_dst, tvb, 20, 8, dst_full);
        proto_item_set_generated(tmp);

        tmp = proto_tree_add_string(ip_tree, hf_ipv8_addr, tvb, 12, 8, src_full);
        proto_item_set_generated(tmp);
        proto_item_set_hidden(tmp);

        tmp = proto_tree_add_string(ip_tree, hf_ipv8_addr, tvb, 20, 8, dst_full);
        proto_item_set_generated(tmp);
        proto_item_set_hidden(tmp);

        proto_item_append_text(ti, ", Src: %s, Dst: %s", src_full, dst_full);

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s %s (%u)",
            src_full, dst_full, ipprotostr(proto), proto);
    }

    /* Set both 32-bit and 64-bit addresses */
    set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, 16);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, 24);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
    
    /* Also create full 64-bit address objects for conversation tracking */
    set_address_tvb(&src64, AT_IPv4, 8, tvb, 12);
    set_address_tvb(&dst64, AT_IPv4, 8, tvb, 20);

    iph = wmem_new0(pinfo->pool, ws_ip8);
    iph->ip8_ver = 8;
    iph->ip8_tos = tvb_get_uint8(tvb, 1);
    iph->ip8_len = total_len;
    iph->ip8_id = tvb_get_ntohs(tvb, 4);
    iph->ip8_off = frag_off;
    iph->ip8_ttl = tvb_get_uint8(tvb, 8);
    iph->ip8_proto = proto;
    iph->ip8_sum = checksum;
    iph->ip8_src_asn = tvb_get_ntohl(tvb, 12);
    iph->ip8_src_host = tvb_get_ntohl(tvb, 16);
    iph->ip8_dst_asn = tvb_get_ntohl(tvb, 20);
    iph->ip8_dst_host = tvb_get_ntohl(tvb, 24);

    /* Dissect options field */
    if (hlen > IPV8_HLEN_MIN) {
        proto_item *opt_item;
        proto_tree *opt_tree;
        
        opt_item = proto_tree_add_item(ip_tree, hf_ipv8_options, tvb, IPV8_HLEN_MIN, 
            hlen - IPV8_HLEN_MIN, ENC_NA);
        opt_tree = proto_item_add_subtree(opt_item, ett_ipv8_options);
        
        dissect_ipv8_options(tvb, IPV8_HLEN_MIN, hlen - IPV8_HLEN_MIN, pinfo, opt_tree);
    }

    save_fragmented = pinfo->fragmented;
    payload_offset = (int)hlen;

    /* Handle fragmentation and reassembly */
    if (ipv8_defragment && tvb_bytes_exist(tvb, 0, total_len) && 
        (frag_off & (IP_MF | IP_OFFSET))) {
        /* This is a fragment */
        uint32_t frag_id;
        uint32_t src32, dst32;
        
        src32 = tvb_get_ntohl(tvb, 16);
        dst32 = tvb_get_ntohl(tvb, 24);
        
        frag_id = iph->ip8_proto ^ iph->ip8_id ^ src32 ^ dst32;
        
        ipv8fd_head = fragment_add_check(&ipv8_reassembly_table, tvb, payload_offset,
            pinfo,
            frag_id,
            NULL,
            (frag_off & IP_OFFSET) * 8,
            iph->ip8_len - hlen,
            frag_off & IP_MF);

        next_tvb = process_reassembled_data(tvb, payload_offset, pinfo,
            "Reassembled IPv8",
            ipv8fd_head, NULL,
            &update_col_info, ip_tree);
    } else if (frag_off & IP_OFFSET) {
        /* Non-first fragment without reassembly enabled */
        next_tvb = NULL;
    } else {
        /* First fragment or not fragmented */
        next_tvb = tvb_new_subset_remaining(tvb, payload_offset);
        if (frag_off & IP_MF)
            pinfo->fragmented = true;
        else
            pinfo->fragmented = false;
    }

    /* Handle reassembly display */
    if (ipv8fd_head && ipv8fd_head->reassembled_in != pinfo->num) {
        col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]",
            ipv8fd_head->reassembled_in);
    }

    /* Handle conversation tracking with 64-bit addresses */
    if (ipv8_track_conv_id) {
        /* Try to find existing conversation using full 64-bit addresses */
        conv = find_conversation(pinfo->num, &src64, &dst64, CONVERSATION_NONE, 0, 0, 0);
        if (!conv) {
            conv = conversation_new(pinfo->num, &src64, &dst64, CONVERSATION_NONE, 0, 0, 0);
        }

        ipv8d = get_ipv8_conversation_data(conv, pinfo);
        if (ipv8d && !pinfo->fd->visited) {
            if (ipv8d->stream == 0) {
                ipv8d->stream = ipv8_stream_count++;
            }
        }
        
        if (ipv8d) {
            item = proto_tree_add_uint(ip_tree, hf_ipv8_reassembled_in, tvb, 0, 0, ipv8d->stream);
            proto_item_set_generated(item);
        }
    }

    if (next_tvb == NULL) {
        /* Just show this as a fragment */
        if (update_col_info && frag_off & IP_OFFSET) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Fragmented IPv8 protocol (proto=%s %u, off=%u, ID=%04x)",
                ipprotostr(iph->ip8_proto), iph->ip8_proto,
                (iph->ip8_off & IP_OFFSET) * 8, iph->ip8_id);
        }
        
        pinfo->fragmented = save_fragmented;
        call_data_dissector(tvb_new_subset_remaining(tvb, payload_offset), pinfo, tree);
        return tvb_captured_length(tvb);
    }

    if (tvb_reported_length(next_tvb) > 0) {
        /* Hand off to next protocol */
        if (!ip_try_dissect(false, proto, next_tvb, pinfo, tree, iph)) {
            /* Unknown protocol */
            if (update_col_info) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)",
                    ipprotostr(iph->ip8_proto), iph->ip8_proto);
            }
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
}

void
proto_register_ipv8(void)
{
    static hf_register_info hf[] = {
        { &hf_ipv8_version,
            { "Version", "ipv8.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_hdr_len,
            { "Header Length", "ipv8.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Header length in 32-bit words", HFILL } },

        { &hf_ipv8_dsfield,
            { "Differentiated Services Field", "ipv8.dsfield", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_len,
            { "Total Length", "ipv8.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_id,
            { "Identification", "ipv8.id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_flags,
            { "Flags", "ipv8.flags", FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL } },

        { &hf_ipv8_flags_rb,
            { "Reserved bit", "ipv8.flags.rb", FT_BOOLEAN, 8, TFS(&flags_set_notset), 0x80, NULL, HFILL } },

        { &hf_ipv8_flags_df,
            { "Don't fragment", "ipv8.flags.df", FT_BOOLEAN, 8, TFS(&flags_set_notset), 0x40, NULL, HFILL } },

        { &hf_ipv8_flags_mf,
            { "More fragments", "ipv8.flags.mf", FT_BOOLEAN, 8, TFS(&flags_set_notset), 0x20, NULL, HFILL } },

        { &hf_ipv8_frag_offset,
            { "Fragment Offset", "ipv8.frag_offset", FT_UINT16, BASE_DEC, NULL, IP_OFFSET, NULL, HFILL } },

        { &hf_ipv8_ttl,
            { "Time to Live", "ipv8.ttl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_proto,
            { "Protocol", "ipv8.proto", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_checksum,
            { "Header Checksum", "ipv8.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_checksum_calculated,
            { "Calculated Checksum", "ipv8.checksum_calculated", FT_UINT16, BASE_HEX, NULL, 0x0,
                "The expected IPv8 checksum field as calculated from the IPv8 datagram", HFILL } },

        { &hf_ipv8_checksum_status,
            { "Header checksum status", "ipv8.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL } },

        { &hf_ipv8_src_asn,
            { "Source ASN Prefix", "ipv8.src_asn", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_src_host,
            { "Source Host Address", "ipv8.src_host", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_dst_asn,
            { "Destination ASN Prefix", "ipv8.dst_asn", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_dst_host,
            { "Destination Host Address", "ipv8.dst_host", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_src,
            { "Source Address", "ipv8.src", FT_STRING, BASE_NONE, NULL, 0x0,
                "Source IPv8 address in r.r.r.r.n.n.n.n notation", HFILL } },

        { &hf_ipv8_dst,
            { "Destination Address", "ipv8.dst", FT_STRING, BASE_NONE, NULL, 0x0,
                "Destination IPv8 address in r.r.r.r.n.n.n.n notation", HFILL } },

        { &hf_ipv8_addr,
            { "Source or Destination Address", "ipv8.addr", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_ipv8_options,
            { "Options", "ipv8.options", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ipv8_reassembled_in,
            { "Reassembled in", "ipv8.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This frame is reassembled in", HFILL } },

        { &hf_ipv8_reassembled_length,
            { "Reassembled IPv8 length", "ipv8.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL } },

        { &hf_ipv8_reassembled_data,
            { "Reassembled IPv8 data", "ipv8.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                "The reassembled payload data", HFILL } },
    };

    static int *ett[] = {
        &ett_ipv8,
        &ett_ipv8_flags,
        &ett_ipv8_options,
    };

    static ei_register_info ei[] = {
        { &ei_ipv8_bogus_version, { "ipv8.bogus_version", PI_PROTOCOL, PI_ERROR, "Bogus IPv8 version", EXPFILL } },
        { &ei_ipv8_bogus_header_length, { "ipv8.bogus_header_length", PI_PROTOCOL, PI_ERROR, "Bogus IPv8 header length", EXPFILL } },
        { &ei_ipv8_bogus_length, { "ipv8.bogus_length", PI_PROTOCOL, PI_ERROR, "Bogus IPv8 length", EXPFILL } },
        { &ei_ipv8_checksum_bad, { "ipv8.checksum_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL } },
    };

    expert_module_t *expert_ipv8;

    proto_ipv8 = proto_register_protocol("Internet Protocol Version 8", "IPv8", "ipv8");
    proto_register_field_array(proto_ipv8, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ipv8 = expert_register_protocol(proto_ipv8);
    expert_register_field_array(expert_ipv8, ei, array_length(ei));

    register_dissector("ipv8", dissect_ipv8, proto_ipv8);
}

void
proto_reg_handoff_ipv8(void)
{
    module_t *ipv8_module;

    /* Register reassembly table */
    reassembly_table_register(&ipv8_reassembly_table, &addresses_reassembly_table_functions);

    /* Register preferences */
    ipv8_module = prefs_register_protocol(proto_ipv8, NULL);

    prefs_register_bool_preference(ipv8_module, "defragment",
        "Reassemble IPv8 fragments",
        "Whether IPv8 fragmented datagrams should be reassembled",
        &ipv8_defragment);

    prefs_register_bool_preference(ipv8_module, "track_conv_id",
        "Track IPv8 conversations",
        "Whether to track IPv8 conversations and assign unique stream IDs",
        &ipv8_track_conv_id);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
