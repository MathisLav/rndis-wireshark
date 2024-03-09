/* packet-rndis.c
 *
 * Routines for RNDIS protocol packet dissection
 * By Mathis L. <rndis@mlavigne.fr.nf>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/dissectors/packet-eth.h>

/* URB */
static int hf_urb_request = -1;
static int hf_urb_wvalue = -1;
static int hf_urb_windex = -1;
static int hf_urb_wlength = -1;

/* Common */
static int proto_rndis = -1;
static int hf_rndis_message_type = -1;
static int hf_rndis_message_length = -1;
static int hf_rndis_reserved_32b = -1;
static int hf_rndis_reserved_64b = -1;

/* PACKET_MSG */
static int hf_rndis_data_offset = -1;
static int hf_rndis_data_length = -1;
static int hf_rndis_oob_data_offset = -1;
static int hf_rndis_oob_data_length = -1;
static int hf_rndis_num_oob_data_elements = -1;
static int hf_rndis_per_packet_info_offset = -1;
static int hf_rndis_per_packet_info_length = -1;
static int hf_rndis_vc_handle = -1;

/* INIT_MSG */
static int hf_rndis_request_id = -1;
static int hf_rndis_major_version = -1;
static int hf_rndis_minor_version = -1;
static int hf_rndis_max_transfer_size = -1;

/* INIT CMPLT */
static int hf_rndis_status = -1;
static int hf_rndis_device_flags = -1;
static int hf_rndis_medium = -1;
static int hf_rndis_max_packets_per_transfer = -1;
static int hf_rndis_packet_alignment_factor = -1;

/* QUERY MSG */
static int hf_rndis_information_buffer_length = -1;
static int hf_rndis_information_buffer_offset = -1;
static int hf_rndis_oid = -1;
static int hf_rndis_oid_buffer = -1;

/* INDICATE MSG */
static int hf_rndis_status_buffer_length = -1;
static int hf_rndis_status_buffer_offset = -1;
static int hf_rndis_diag_status = -1;
static int hf_rndis_error_offset = -1;
static int hf_rndis_status_buffer = -1;


static dissector_handle_t eth_dissector;
static int ett_rndis;
static gint ett_diag_inf;

#define DATA_MSG_ID 0x00000001
#define INIT_MSG_ID 0x00000002
#define INIT_CMPLT_ID 0x80000002
#define HALT_MSG_ID 0x00000003
#define QUERY_MSG_ID 0x00000004
#define QUERY_CMPLT_ID 0x80000004
#define SET_MSG_ID 0x00000005
#define SET_CMPLT_ID 0x80000005
#define RESET_MSG_ID 0x00000006
#define RESET_CMPLT_ID 0x80000006
#define INDICATE_MSG_ID 0x00000007
#define KEEPALIVE_MSG_ID 0x00000008
#define KEEPALIVE_CMPLT_ID 0x80000008

static const value_string message_type_names[] = {
    {DATA_MSG_ID, "DATA_MSG"},
    {INIT_MSG_ID, "INIT_MSG"},
    {INIT_CMPLT_ID, "INIT_CMPLT"},
    {HALT_MSG_ID, "HALT_MSG"},
    {QUERY_MSG_ID, "QUERY_MSG"},
    {QUERY_CMPLT_ID, "QUERY_CMPLT"},
    {SET_MSG_ID, "SET_MSG"},
    {SET_CMPLT_ID, "SET_CMPLT"},
    {RESET_MSG_ID, "RESET_MSG"},
    {RESET_CMPLT_ID, "RESET_CMPLT"},
    {INDICATE_MSG_ID, "INDICATE_MSG"},
    {KEEPALIVE_MSG_ID, "KEEPALIVE_MSG"},
    {KEEPALIVE_CMPLT_ID, "KEEPALIVE_CMPLT"},
    {0, NULL}
};

static const value_string status_names[] = {
    { 0x00000000, "RNDIS_STATUS_SUCCESS" },
    { 0xC0000001, "RNDIS_STATUS_FAILURE" },
    { 0xC0010015, "RNDIS_STATUS_INVALID_DATA" },
    { 0xC00000BB, "RNDIS_STATUS_NOT_SUPPORTED" },
    { 0x4001000B, "RNDIS_STATUS_MEDIA_CONNECT" },
    { 0x4001000C, "RNDIS_STATUS_MEDIA_DISCONNECT" }, 
    {0, NULL}
};

static const value_string OIDs[] = {
    /* General OIDs */
    { 0x00010101, "OID_GEN_SUPPORTED_LIST" },
    { 0x00010102, "OID_GEN_HARDWARE_STATUS" },
    { 0x00010103, "OID_GEN_MEDIA_SUPPORTED" },
    { 0x00010104, "OID_GEN_MEDIA_IN_USE" },
    { 0x00010105, "OID_GEN_MAXIMUM_LOOKAHEAD" },
    { 0x00010106, "OID_GEN_MAXIMUM_FRAME_SIZE" },
    { 0x00010107, "OID_GEN_LINK_SPEED" },
    { 0x00010108, "OID_GEN_TRANSMIT_BUFFER_SPACE" },
    { 0x00010109, "OID_GEN_RECEIVE_BUFFER_SPACE" },
    { 0x0001010A, "OID_GEN_TRANSMIT_BLOCK_SIZE" },
    { 0x0001010B, "OID_GEN_RECEIVE_BLOCK_SIZE" },
    { 0x0001010C, "OID_GEN_VENDOR_ID" },
    { 0x0001010D, "OID_GEN_VENDOR_DESCRIPTION" },
    { 0x0001010E, "OID_GEN_CURRENT_PACKET_FILTER" },
    { 0x0001010F, "OID_GEN_CURRENT_LOOKAHEAD" },
    { 0x00010110, "OID_GEN_DRIVER_VERSION" },
    { 0x00010111, "OID_GEN_MAXIMUM_TOTAL_SIZE" },
    { 0x00010112, "OID_GEN_PROTOCOL_OPTIONS" },
    { 0x00010113, "OID_GEN_MAC_OPTIONS" },
    { 0x00010114, "OID_GEN_MEDIA_CONNECT_STATUS" },
    { 0x00010115, "OID_GEN_MAXIMUM_SEND_PACKETS" },
    { 0x00010116, "OID_GEN_VENDOR_DRIVER_VERSION" },
    { 0x00010117, "OID_GEN_SUPPORTED_GUIDS" },
    { 0x00010118, "OID_GEN_NETWORK_LAYER_ADDRESSES" },
    { 0x00010119, "OID_GEN_TRANSPORT_HEADER_OFFSET" },
    { 0x0001021A, "OID_GEN_MACHINE_NAME" },
    { 0x0001021B, "OID_GEN_RNDIS_CONFIG_PARAMETER" },
    { 0x0001021C, "OID_GEN_VLAN_ID" },
    /* Optional OIDs */
    { 0x00010201, "OID_GEN_MEDIA_CAPABILITIES" },
    { 0x00010202, "OID_GEN_PHYSICAL_MEDIUM" },
    /* Required statistics OIDs */
    { 0x00020101, "OID_GEN_XMIT_OK" },
    { 0x00020102, "OID_GEN_RCV_OK" },
    { 0x00020103, "OID_GEN_XMIT_ERROR" },
    { 0x00020104, "OID_GEN_RCV_ERROR" },
    { 0x00020105, "OID_GEN_RCV_NO_BUFFER" },
    /* Optional statistics OIDs */
    { 0x00020201, "OID_GEN_DIRECTED_BYTES_XMIT" },
    { 0x00020202, "OID_GEN_DIRECTED_FRAMES_XMIT" },
    { 0x00020203, "OID_GEN_MULTICAST_BYTES_XMIT" },
    { 0x00020204, "OID_GEN_MULTICAST_FRAMES_XMIT" },
    { 0x00020205, "OID_GEN_BROADCAST_BYTES_XMIT" },
    { 0x00020206, "OID_GEN_BROADCAST_FRAMES_XMIT" },
    { 0x00020207, "OID_GEN_DIRECTED_BYTES_RCV" },
    { 0x00020208, "OID_GEN_DIRECTED_FRAMES_RCV" },
    { 0x00020209, "OID_GEN_MULTICAST_BYTES_RCV" },
    { 0x0002020A, "OID_GEN_MULTICAST_FRAMES_RCV" },
    { 0x0002020B, "OID_GEN_BROADCAST_BYTES_RCV" },
    { 0x0002020C, "OID_GEN_BROADCAST_FRAMES_RCV" },
    { 0x0002020D, "OID_GEN_RCV_CRC_ERROR" },
    { 0x0002020E, "OID_GEN_TRANSMIT_QUEUE_LENGTH" },
    { 0x0002020F, "OID_GEN_GET_TIME_CAPS" },
    { 0x00020210, "OID_GEN_GET_NETCARD_TIME" },
    { 0x00020211, "OID_GEN_NETCARD_LOAD" },
    { 0x00020212, "OID_GEN_DEVICE_PROFILE" },
    { 0x00020213, "OID_GEN_INIT_TIME_MS" },
    { 0x00020214, "OID_GEN_RESET_COUNTS" },
    { 0x00020215, "OID_GEN_MEDIA_SENSE_COUNTS" },
    { 0x00020216, "OID_GEN_FRIENDLY_NAME" },
    { 0x00020217, "OID_GEN_MINIPORT_INFO" },
    { 0x00020218, "OID_GEN_RESET_VERIFY_PARAMETERS" },
    /* IEEE 802.3 (Ethernet) OIDs */
    { 0x00000001, "NDIS_802_3_MAC_OPTION_PRIORITY" },
    { 0x01010101, "OID_802_3_PERMANENT_ADDRESS" },
    { 0x01010102, "OID_802_3_CURRENT_ADDRESS" },
    { 0x01010103, "OID_802_3_MULTICAST_LIST" },
    { 0x01010104, "OID_802_3_MAXIMUM_LIST_SIZE" },
    { 0x01010105, "OID_802_3_MAC_OPTIONS" },
    { 0x01020101, "OID_802_3_RCV_ERROR_ALIGNMENT" },
    { 0x01020102, "OID_802_3_XMIT_ONE_COLLISION" },
    { 0x01020103, "OID_802_3_XMIT_MORE_COLLISIONS" },
    { 0x01020201, "OID_802_3_XMIT_DEFERRED" },
    { 0x01020202, "OID_802_3_XMIT_MAX_COLLISIONS" },
    { 0x01020203, "OID_802_3_RCV_OVERRUN" },
    { 0x01020204, "OID_802_3_XMIT_UNDERRUN" },
    { 0x01020205, "OID_802_3_XMIT_HEARTBEAT_FAILURE" },
    { 0x01020206, "OID_802_3_XMIT_TIMES_CRS_LOST" },
    { 0x01020207, "OID_802_3_XMIT_LATE_COLLISIONS" },
    /* Wireless LAN OIDs */
    { 0x0D010101, "OID_802_11_BSSID" },
    { 0x0D010102, "OID_802_11_SSID" },
    { 0x0D010204, "OID_802_11_NETWORK_TYPE_IN_USE" },
    { 0x0D010206, "OID_802_11_RSSI" },
    { 0x0D010217, "OID_802_11_BSSID_LIST" },
    { 0x0D01011A, "OID_802_11_BSSID_LIST_SCAN" },
    { 0x0D010108, "OID_802_11_INFRASTRUCTURE_MODE" },
    { 0x0D01020E, "OID_802_11_SUPPORTED_RATES" },
    { 0x0D010211, "OID_802_11_CONFIGURATION" },
    { 0x0D010113, "OID_802_11_ADD_WEP" },
    { 0x0D01011B, "OID_802_11_WEP_STATUS" },
    { 0x0D010114, "OID_802_11_REMOVE_WEP" },
    { 0x0D010115, "OID_802_11_DISASSOCIATE" },
    { 0x0D010118, "OID_802_11_AUTHENTICATION_MODE" },
    { 0x0D01011C, "OID_802_11_RELOAD_DEFAULTS" },
    {0, NULL}
};

/* As RNDIS messages canNOT be sent simultaneously, no need to use complex data structures to have a context */
static gint cur_oid = -1;  /* The OID of the Set/Query MSG request */

static int
dissect_packet_rndis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const guint16 length = tvb_reported_length(tvb);
    if(length == 0) {
        return tvb_captured_length(tvb);
    }

    if(tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN) == DATA_MSG_ID) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RNDIS");
        proto_item *ti = proto_tree_add_item(tree, proto_rndis, tvb, 0, -1, ENC_NA);
        proto_tree *rndis_tree = proto_item_add_subtree(ti, ett_rndis);
        proto_tree_add_item(rndis_tree, hf_rndis_message_type, tvb, 0, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_message_length, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_data_offset, tvb, 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_data_length, tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_oob_data_offset, tvb, 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_oob_data_length, tvb, 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_num_oob_data_elements, tvb, 24, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_per_packet_info_offset, tvb, 28, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_per_packet_info_length, tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_vc_handle, tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rndis_tree, hf_rndis_reserved_32b, tvb, 40, 4, ENC_LITTLE_ENDIAN);
        if(length >= 44 + 14) {
            /* Dissect Ethernet header */
            tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, 44);
            call_dissector(eth_dissector, next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_control_rndis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const guint16 length = tvb_reported_length(tvb);
    if(length <= 7) {
        return tvb_captured_length(tvb);
    }

    tvbuff_t *rndis_tvb;
    if(tvb_get_guint8(tvb, 0) == 0) {
        proto_tree_add_item(tree, hf_urb_request, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_urb_wvalue, tvb, 1, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_urb_windex, tvb, 3, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_urb_wlength, tvb, 5, 2, ENC_LITTLE_ENDIAN);

        rndis_tvb = tvb_new_subset_remaining(tvb, 7);
    } else {
        rndis_tvb = tvb;
    }
    const guint16 rndis_length = tvb_reported_length(rndis_tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RNDIS");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *rndis_ti = proto_tree_add_item(tree, proto_rndis, rndis_tvb, 0, -1, ENC_NA);
    proto_tree *rndis_tree = proto_item_add_subtree(rndis_ti, ett_rndis);

    switch(tvb_get_guint32(rndis_tvb, 0, ENC_LITTLE_ENDIAN)) {
        case INIT_MSG_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS INIT_MSG");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_major_version, rndis_tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_minor_version, rndis_tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_max_transfer_size, rndis_tvb, 20, 4, ENC_LITTLE_ENDIAN);
            break;
        case INIT_CMPLT_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS INIT_CMPLT");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_major_version, tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_minor_version, tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_device_flags, tvb, 24, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_medium, tvb, 28, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_max_packets_per_transfer, tvb, 32, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_max_transfer_size, tvb, 36, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_packet_alignment_factor, tvb, 40, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_reserved_64b, tvb, 44, 8, ENC_LITTLE_ENDIAN);
            break;
        case HALT_MSG_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS Halt MSG");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            break;
        case QUERY_MSG_ID: {
            const int oid = tvb_get_guint32(rndis_tvb, 12, ENC_LITTLE_ENDIAN);
            cur_oid = oid;
            col_add_fstr(pinfo->cinfo, COL_INFO, "RNDIS Query MSG   (%s)", val_to_str(oid, OIDs, "Unknown (0x%08x)"));
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_oid, rndis_tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_length, rndis_tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_offset, rndis_tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_vc_handle, rndis_tvb, 24, 4, ENC_LITTLE_ENDIAN);
            if(rndis_length > 28) {
                proto_tree_add_item(rndis_tree, hf_rndis_oid_buffer, rndis_tvb, 28, -1, ENC_LITTLE_ENDIAN);
            }
            break;
        }
        case QUERY_CMPLT_ID:
            col_add_fstr(pinfo->cinfo, COL_INFO, "RNDIS Query CMPLT (%s)", val_to_str(cur_oid, OIDs, "Unknown (0x%08x)"));
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_length, rndis_tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_offset, rndis_tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_oid_buffer, rndis_tvb, 24, -1, ENC_LITTLE_ENDIAN);
            break;
        case SET_MSG_ID: {
            const int oid = tvb_get_guint32(rndis_tvb, 12, ENC_LITTLE_ENDIAN);
            cur_oid = oid;
            col_add_fstr(pinfo->cinfo, COL_INFO, "RNDIS Set MSG   (%s)", val_to_str(oid, OIDs, "Unknown (0x%08x)"));
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_oid, rndis_tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_length, rndis_tvb, 16, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_information_buffer_offset, rndis_tvb, 20, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_vc_handle, rndis_tvb, 24, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_oid_buffer, rndis_tvb, 28, -1, ENC_LITTLE_ENDIAN);
            break;
        }
        case SET_CMPLT_ID:
            col_add_fstr(pinfo->cinfo, COL_INFO, "RNDIS Set CMPLT (%s)", val_to_str(cur_oid, OIDs, "Unknown (0x%08x)"));
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        case RESET_MSG_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS Reset MSG");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            break;
        case RESET_CMPLT_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS Reset CMPLT");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        case INDICATE_MSG_ID:
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status_buffer_length, rndis_tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status_buffer_offset, rndis_tvb, 16, 4, ENC_LITTLE_ENDIAN);
            if(tvb_get_guint32(rndis_tvb, 12, ENC_LITTLE_ENDIAN) + 20 <= rndis_length) {
                proto_item *diag_inf_tree = proto_tree_add_subtree(rndis_tree, rndis_tvb, 20, 8, ett_diag_inf, NULL, "Diagnostic Info Buffer");
                proto_tree_add_item(diag_inf_tree, hf_rndis_diag_status, rndis_tvb, 20, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(diag_inf_tree, hf_rndis_error_offset, rndis_tvb, 24, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(rndis_tree, hf_rndis_status_buffer, rndis_tvb, 28, -1, ENC_LITTLE_ENDIAN);
            } else {
                proto_tree_add_item(rndis_tree, hf_rndis_status_buffer, rndis_tvb, 20, -1, ENC_LITTLE_ENDIAN);
            }
            break;
        case KEEPALIVE_MSG_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS Keepalive MSG");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            break;
        case KEEPALIVE_CMPLT_ID:
            col_set_str(pinfo->cinfo, COL_INFO, "RNDIS Keepalive CMPLT");
            proto_tree_add_item(rndis_tree, hf_rndis_message_type, rndis_tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_message_length, rndis_tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_request_id, rndis_tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(rndis_tree, hf_rndis_status, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            break;
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_rndis(void)
{
    static hf_register_info hf[] = {
        { &hf_urb_request,
          { "Request Type", "urb.request",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "URB Request Type", HFILL }},
        { &hf_urb_wvalue,
          { "Value", "urb.wvalue",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "URB Value", HFILL }},
        { &hf_urb_windex,
          { "Index", "urb.windex",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "URB Index", HFILL }},
        { &hf_urb_wlength,
          { "Transfer Length", "urb.wlength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "URB Transfer Length", HFILL }},
        { &hf_rndis_message_type,
          { "Message Type", "rndis.message_type",
            FT_UINT32, BASE_HEX, VALS(message_type_names), 0x0,
            "RNDIS Message Type", HFILL }},
        { &hf_rndis_message_length,
          { "Message Length", "rndis.message_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Message Length", HFILL }},
        { &hf_rndis_data_offset,
          { "Data Offset", "rndis.data_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Data Offset", HFILL }},
        { &hf_rndis_data_length,
          { "Data Length", "rndis.data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Data Length", HFILL }},
        { &hf_rndis_oob_data_offset,
          { "Out-of-Band Data Offset", "rndis.oob_data_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Out-of-Band Data Offset", HFILL }},
        { &hf_rndis_oob_data_length,
          { "Out-of-Band Data Length", "rndis.oob_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Out-of-Band Data Length", HFILL }},
        { &hf_rndis_num_oob_data_elements,
          { "Number of Out-of-Band Data Elements", "rndis.num_oob_data_elements",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Number of Out-of-Band Data Elements", HFILL }},
        { &hf_rndis_per_packet_info_offset,
          { "Per-Packet Info Offset", "rndis.per_packet_info_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Per-Packet Info Offset", HFILL }},
        { &hf_rndis_per_packet_info_length,
          { "Per-Packet Info Length", "rndis.per_packet_info_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Per-Packet Info Length", HFILL }},
        { &hf_rndis_vc_handle,
          { "VC Handle", "rndis.vc_handle",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS VC Handle", HFILL }},
        { &hf_rndis_reserved_32b,
          { "Reserved", "rndis.reserved",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Reserved", HFILL }},
        { &hf_rndis_reserved_64b,
          { "Reserved", "rndis.reserved",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "RNDIS Reserved", HFILL }},
        { &hf_rndis_request_id,
          { "Request ID", "rndis.request_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Request ID", HFILL }},
        { &hf_rndis_major_version,
          { "Major Version", "rndis.major_version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Major Version", HFILL }},
        { &hf_rndis_minor_version,
          { "Minor Version", "rndis.minor_version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Minor Version", HFILL }},
        { &hf_rndis_max_transfer_size,
          { "Max Transfer Size", "rndis.max_transfer_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Max Transfer Size", HFILL }},
        { &hf_rndis_status,
          { "Status", "rndis.status",
            FT_UINT32, BASE_HEX, VALS(status_names), 0x0,
            "RNDIS Status", HFILL }},
        { &hf_rndis_device_flags,
          { "Device Flags", "rndis.device_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "RNDIS Device Flags", HFILL }},
        { &hf_rndis_medium,
          { "Medium", "rndis.medium",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "RNDIS Medium", HFILL }},
        { &hf_rndis_max_packets_per_transfer,
          { "Max Packets Per Transfer", "rndis.max_packets_per_transfer",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Max Packets Per Transfer", HFILL }},
        { &hf_rndis_packet_alignment_factor,
          { "Packet Alignment Factor", "rndis.packet_alignment_factor",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Packet Alignment Factor", HFILL }},
        { &hf_rndis_information_buffer_length,
          { "Information Buffer Length", "rndis.info_bufer_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Information Buffer Length", HFILL }},
        { &hf_rndis_information_buffer_offset,
          { "Information Buffer Offset", "rndis.info_bufer_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Information Buffer Offset", HFILL }},
        { &hf_rndis_oid,
          { "OID", "rndis.oid",
            FT_UINT32, BASE_HEX, VALS(OIDs), 0x0,
            "RNDIS OID", HFILL }},
        { &hf_rndis_oid_buffer,
          { "OID Buffer", "rndis.oid_buffer",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "RNDIS OID Buffer", HFILL }},
        { &hf_rndis_status_buffer_length,
          { "Status Buffer Length", "rndis.status_buffer_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Status Buffer Length", HFILL }},
        { &hf_rndis_status_buffer_offset,
          { "Status Buffer Offset", "rndis.status_buffer_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Status Buffer Offset", HFILL }},
        { &hf_rndis_diag_status,
          { "Diagnostic Status", "rndis.diag_status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "RNDIS Diagnostic Status", HFILL }},
        { &hf_rndis_error_offset,
          { "Error Offset", "rndis.error_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "RNDIS Error Offset", HFILL }},
        { &hf_rndis_status_buffer,
          { "Status Buffer", "rndis.status_buffer",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "RNDIS Status Buffer", HFILL }},
        };

    proto_rndis = proto_register_protocol (
        "Remote NDIS Protocol", /* name        */
        "RNDIS",          /* short_name  */
        "rndis"           /* filter_name */
        );

    static int *ett[] = {
        &ett_rndis,
        &ett_diag_inf
    };

    proto_register_field_array(proto_rndis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rndis(void)
{
    static dissector_handle_t rndis_packet_handle;
    static dissector_handle_t rndis_control_handle;

    rndis_packet_handle = create_dissector_handle(dissect_packet_rndis, proto_rndis);
    dissector_add_uint("usb.bulk", 0x0a, rndis_packet_handle);

    rndis_control_handle = create_dissector_handle(dissect_control_rndis, proto_rndis);
    dissector_add_uint("usb.control", 0xe0, rndis_control_handle);

    eth_dissector = find_dissector("eth_withoutfcs");
}
