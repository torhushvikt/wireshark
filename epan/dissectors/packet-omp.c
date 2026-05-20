/* packet-omp.c
 * Routines for Overlay Management Protocol (OMP) dissection
 * Cisco SD-WAN proprietary protocol
 *
 * OMP is a BGP-like routing protocol that runs inside DTLS/TLS tunnels
 * between Cisco SD-WAN Controllers (vSmart) and edge routers (vEdge).
 * It carries routes, TLOCs (Transport Locations), encryption keys, and
 * policy information for the SD-WAN overlay network.
 *
 * References:
 * - Cisco Catalyst SD-WAN documentation
 * - OMP runs inside DTLS on control plane connections (typically port 23456)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void proto_register_omp(void);
void proto_reg_handoff_omp(void);

/* Protocol handle */
static int proto_omp;

/* Dissector handle */
static dissector_handle_t omp_handle;

/* Header fields */
static int hf_omp_version;
static int hf_omp_message_type;
static int hf_omp_length;
static int hf_omp_flags;

/* Message types (to be determined from packet captures) */
#define OMP_MSG_TYPE_UNKNOWN        0
#define OMP_MSG_TYPE_UPDATE         1  /* Route advertisement */
#define OMP_MSG_TYPE_WITHDRAW       2  /* Route withdrawal */
#define OMP_MSG_TYPE_KEEPALIVE      3  /* Keepalive */
#define OMP_MSG_TYPE_NOTIFICATION   4  /* Error notification */

static const value_string omp_message_types[] = {
    { OMP_MSG_TYPE_UNKNOWN,      "Unknown" },
    { OMP_MSG_TYPE_UPDATE,       "Update" },
    { OMP_MSG_TYPE_WITHDRAW,     "Withdraw" },
    { OMP_MSG_TYPE_KEEPALIVE,    "Keepalive" },
    { OMP_MSG_TYPE_NOTIFICATION, "Notification" },
    { 0, NULL }
};

/* Route types */
static int hf_omp_route_type;

#define OMP_ROUTE_OMP        1  /* OMP route (prefix) */
#define OMP_ROUTE_TLOC       2  /* Transport Location */
#define OMP_ROUTE_SERVICE    3  /* Service route */

static const value_string omp_route_types[] = {
    { OMP_ROUTE_OMP,     "OMP Route" },
    { OMP_ROUTE_TLOC,    "TLOC" },
    { OMP_ROUTE_SERVICE, "Service Route" },
    { 0, NULL }
};

/* Subtree indices */
static int ett_omp;
static int ett_omp_header;
static int ett_omp_route;
static int ett_omp_tloc;

/* Expert info */
static expert_field ei_omp_invalid_length;
static expert_field ei_omp_unknown_version;

/*
 * Heuristic dissector to identify OMP traffic inside DTLS
 * OMP should be identifiable by:
 * - Specific byte patterns in header
 * - Known message structure
 * - BGP-like TLV format
 */
static bool
dissect_omp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Need at least a minimal header to identify OMP */
    if (tvb_captured_length(tvb) < 4)
        return false;

    /* TODO: Add heuristic checks based on actual packet captures
     * For now, we'll check for reasonable values
     * This is a placeholder - real heuristics need packet analysis
     */

    uint8_t version = tvb_get_uint8(tvb, 0);
    uint8_t msg_type = tvb_get_uint8(tvb, 1);

    /* Basic sanity checks - adjust based on real protocol */
    if (version > 10)  /* Unlikely to have version > 10 */
        return false;
    
    if (msg_type > 20)  /* Message types should be in reasonable range */
        return false;

    /* If checks pass, dissect as OMP */
    dissect_omp(tvb, pinfo, tree, data);
    return true;
}

/*
 * Main dissector function
 */
static int
dissect_omp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *omp_tree;
    proto_tree *header_tree;
    uint32_t offset = 0;
    uint32_t msg_len;
    uint8_t version;
    uint8_t msg_type;

    /* Set protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OMP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Check minimum packet size */
    if (tvb_reported_length(tvb) < 4) {
        col_set_str(pinfo->cinfo, COL_INFO, "Malformed packet");
        return tvb_captured_length(tvb);
    }

    /* Get basic header info for info column */
    version = tvb_get_uint8(tvb, offset);
    msg_type = tvb_get_uint8(tvb, offset + 1);

    col_add_fstr(pinfo->cinfo, COL_INFO, "OMP v%u: %s",
                 version,
                 val_to_str(msg_type, omp_message_types, "Unknown (0x%02x)"));

    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_omp, tvb, 0, -1, ENC_NA);
    omp_tree = proto_item_add_subtree(ti, ett_omp);

    /* Add header subtree */
    header_tree = proto_tree_add_subtree(omp_tree, tvb, offset, 4,
                                         ett_omp_header, NULL, "OMP Header");

    /* Version field */
    proto_tree_add_item(header_tree, hf_omp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Message type */
    proto_tree_add_item(header_tree, hf_omp_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Length field (assuming 2-byte length) */
    proto_tree_add_item_ret_uint(header_tree, hf_omp_length, tvb, offset, 2,
                                  ENC_BIG_ENDIAN, &msg_len);
    offset += 2;

    /* Validate length */
    if (msg_len > tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info(pinfo, ti, &ei_omp_invalid_length);
        return tvb_captured_length(tvb);
    }

    /* TODO: Parse message body based on message type
     * This requires understanding the actual protocol structure
     * from packet captures or documentation
     */

    switch (msg_type) {
    case OMP_MSG_TYPE_UPDATE:
        /* Parse UPDATE message - would contain routes, TLOCs, keys */
        col_append_str(pinfo->cinfo, COL_INFO, " [Routes]");
        /* TODO: Implement route parsing */
        break;

    case OMP_MSG_TYPE_WITHDRAW:
        /* Parse WITHDRAW message */
        col_append_str(pinfo->cinfo, COL_INFO, " [Withdrawal]");
        break;

    case OMP_MSG_TYPE_KEEPALIVE:
        /* Keepalive messages might be simple */
        col_append_str(pinfo->cinfo, COL_INFO, " [Keepalive]");
        break;

    case OMP_MSG_TYPE_NOTIFICATION:
        /* Error notifications */
        col_append_str(pinfo->cinfo, COL_INFO, " [Notification]");
        break;

    default:
        /* Unknown message type - display as raw data */
        break;
    }

    return tvb_captured_length(tvb);
}

/*
 * Protocol registration
 */
void
proto_register_omp(void)
{
    static hf_register_info hf[] = {
        { &hf_omp_version,
          { "Version", "omp.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "OMP Protocol Version", HFILL }
        },
        { &hf_omp_message_type,
          { "Message Type", "omp.type",
            FT_UINT8, BASE_DEC, VALS(omp_message_types), 0x0,
            "OMP Message Type", HFILL }
        },
        { &hf_omp_length,
          { "Length", "omp.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Message Length", HFILL }
        },
        { &hf_omp_flags,
          { "Flags", "omp.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "OMP Flags", HFILL }
        },
        { &hf_omp_route_type,
          { "Route Type", "omp.route.type",
            FT_UINT8, BASE_DEC, VALS(omp_route_types), 0x0,
            "Type of OMP route", HFILL }
        }
    };

    static int *ett[] = {
        &ett_omp,
        &ett_omp_header,
        &ett_omp_route,
        &ett_omp_tloc
    };

    static ei_register_info ei[] = {
        { &ei_omp_invalid_length,
          { "omp.invalid_length", PI_MALFORMED, PI_ERROR,
            "Invalid message length", EXPFILL }
        },
        { &ei_omp_unknown_version,
          { "omp.unknown_version", PI_PROTOCOL, PI_WARN,
            "Unknown OMP version", EXPFILL }
        }
    };

    expert_module_t *expert_omp;

    /* Register protocol */
    proto_omp = proto_register_protocol(
        "Overlay Management Protocol",  /* Full name */
        "OMP",                          /* Short name */
        "omp"                           /* Filter name */
    );

    /* Register fields and subtrees */
    proto_register_field_array(proto_omp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert info */
    expert_omp = expert_register_protocol(proto_omp);
    expert_register_field_array(expert_omp, ei, array_length(ei));

    /* Register dissector handle */
    omp_handle = register_dissector("omp", dissect_omp, proto_omp);
}

/*
 * Protocol handoff - register with DTLS/TLS and other protocols
 */
void
proto_reg_handoff_omp(void)
{
    /* Register as a heuristic dissector for DTLS
     * OMP runs inside DTLS tunnels on control plane connections
     */
    heur_dissector_add("dtls", dissect_omp_heur, "OMP over DTLS", "omp_dtls", proto_omp, HEURISTIC_ENABLE);
    
    /* Also register for TLS (TLS 1.3 support was added in newer versions) */
    heur_dissector_add("tls", dissect_omp_heur, "OMP over TLS", "omp_tls", proto_omp, HEURISTIC_ENABLE);

    /* Could also register on specific ports if needed
     * Port 23456 is mentioned in documentation for control connections
     */
    /* dissector_add_uint("dtls.port", 23456, omp_handle); */
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
