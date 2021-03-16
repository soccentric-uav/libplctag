/***************************************************************************
 *   Copyright (C) 2021 by Kyle Hayes                                      *
 *   Author Kyle Hayes  kyle.hayes@gmail.com                               *
 *                                                                         *
 * This software is available under either the Mozilla Public License      *
 * version 2.0 or the GNU LGPL version 2 (or later) license, whichever     *
 * you choose.                                                             *
 *                                                                         *
 * MPL 2.0:                                                                *
 *                                                                         *
 *   This Source Code Form is subject to the terms of the Mozilla Public   *
 *   License, v. 2.0. If a copy of the MPL was not distributed with this   *
 *   file, You can obtain one at http://mozilla.org/MPL/2.0/.              *
 *                                                                         *
 *                                                                         *
 * LGPL 2:                                                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ab2/ab.h>
#include <ab2/cip.h>
#include <ab2/cip_layer.h>
#include <ab2/eip_layer.h>
#include <lib/libplctag.h>
#include <util/atomic_int.h>
#include <util/attr.h>
#include <util/debug.h>
#include <util/mem.h>
#include <util/mutex.h>
#include <util/plc.h>
#include <util/socket.h>
#include <util/string.h>



//#define CIP_CONN_PARAM ((uint16_t)0x4200)
//0100 0011 1111 1000
//0100 001 1 1111 1000
#define CIP_CONN_PARAM_EX ((uint32_t)0x42000000)
#define CIP_CONN_PARAM ((uint16_t)0x4200)
// #define LOGIX_LARGE_PAYLOAD_SIZE (4002)

#define CIP_CMD_EXECUTED_FLAG ((uint8_t)0x80)
#define CIP_FORWARD_CLOSE_REQUEST ((uint8_t)0x4E)
#define CIP_FORWARD_OPEN_REQUEST ((uint8_t)0x54)
#define CIP_FORWARD_OPEN_REQUEST_EX ((uint8_t)0x5B)

#define CIP_SERVICE_STATUS_OK   (0x00)

#define CIP_ERR_UNSUPPORTED (0x08)
#define CIP_ERR_NO_RESOURCES (0x02)

#define CPF_UNCONNECTED_HEADER_SIZE (16)
#define CPF_CONNECTED_HEADER_SIZE (20)

#define CIP_PAYLOAD_HEADER_FUDGE (40)  /* Measured, might even be right. */

/* CPF definitions */

/* Unconnected data item type */
#define CPF_UNCONNECTED_ADDRESS_ITEM ((uint16_t)0x0000)
#define CPF_UNCONNECTED_DATA_ITEM ((uint16_t)0x00B2)
#define CPF_CONNECTED_ADDRESS_ITEM ((uint16_t)0x00A1)
#define CPF_CONNECTED_DATA_ITEM ((uint16_t)0x00B1)

/* forward open constants */
#define FORWARD_OPEN_SECONDS_PER_TICK (10)
#define FORWARD_OPEN_TIMEOUT_TICKS  (5)
#define CIP_TIMEOUT_MULTIPLIER (1)
#define CIP_RPI_uS (1000000)
#define CIP_CONNECTION_TYPE (0xA3)


#define MAX_CIP_PATH_SIZE (256)


struct cip_layer_s {
    struct plc_layer_s base_layer;

    plc_p plc;

    bool forward_open_ex_enabled;

    uint16_t cip_payload_ex;
    uint16_t cip_payload;

    uint16_t sequence_id;
    uint32_t connection_id;
    uint32_t plc_connection_id;

    int cip_header_start_offset;

    bool is_dhp;
    uint8_t dhp_port;
    uint8_t dhp_dest;

    int encoded_path_size;
    uint8_t encoded_path[];
};


typedef struct cip_layer_s *cip_layer_p;


static int cip_layer_initialize(plc_layer_p layer_arg);
static int cip_layer_connect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);
static int cip_layer_disconnect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);
static int cip_layer_reserve_space(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int cip_layer_build_layer(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int cip_layer_process_response(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int cip_layer_destroy_layer(plc_layer_p layer_arg);

static int process_forward_open_response(struct cip_layer_s *state, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);
static int process_forward_close_response(struct cip_layer_s *state, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);

// static int encode_cip_path(struct cip_layer_s *state, uint8_t *data, int data_capacity, int *data_offset, const char *path);
// static int encode_bridge_segment(struct cip_layer_s *state, uint8_t *data, int data_capacity, int *data_offset, char **path_segments, int *segment_index);
// static int encode_dhp_addr_segment(struct cip_layer_s *state, uint8_t *data, int data_capacity, int *data_offset, char **path_segments, int *segment_index);
// static int encode_numeric_segment(struct cip_layer_s *state, uint8_t *data, int data_capacity, int *data_offset, char **path_segments, int *segment_index);




int cip_layer_setup(plc_p plc, attr attribs, plc_layer_p *result)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = NULL;
    const char *path = NULL;
    int encoded_path_size = 0;
    int cip_payload_size = 0;
    bool is_dhp = false;
    uint8_t dhp_port = 0;
    uint8_t dhp_id = 0;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(plc));

    path = attr_get_str(attribs, "path", "");

    /* call once for the size and validation. */
    pdebug(DEBUG_DETAIL, "Get CIP path length.");
    rc = ab2_cip_encode_path(NULL, MAX_CIP_PATH_SIZE, &encoded_path_size, path, &is_dhp, &dhp_port, &dhp_id);
    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Path, \"%s\", check failed with error %s!", path, plc_tag_decode_error(rc));
        return rc;
    }

    pdebug(DEBUG_DETAIL, "Encoded CIP path size: %d.", encoded_path_size);

    /* now we have the size so we can allocate the state. */

    state = mem_alloc((int)(unsigned int)sizeof(*state) + encoded_path_size);
    if(!state) {
        pdebug(DEBUG_WARN, "Unable to allocate CIP layer state!");
        return PLCTAG_ERR_NO_MEM;
    }

    /* fill in static/base layer data. */
    state->plc = plc;
    state->base_layer.is_connected = false;
    state->base_layer.initialize = cip_layer_initialize;
    state->base_layer.connect = cip_layer_connect;
    state->base_layer.disconnect = cip_layer_disconnect;
    state->base_layer.reserve_space = cip_layer_reserve_space;
    state->base_layer.build_layer = cip_layer_build_layer;
    state->base_layer.process_response = cip_layer_process_response;
    state->base_layer.destroy_layer = cip_layer_destroy_layer;

    /* now encode it for real */
    pdebug(DEBUG_DETAIL, "Encode CIP path.");
    state->encoded_path_size = 0;
    rc = ab2_cip_encode_path(&(state->encoded_path[0]), encoded_path_size, &(state->encoded_path_size), path, &is_dhp, &dhp_port, &dhp_id);
    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Path, \"%s\", encoding failed with error %s!", path, plc_tag_decode_error(rc));
        return rc;
    }

    state->is_dhp = is_dhp;
    state->dhp_port = dhp_port;
    state->dhp_dest = dhp_id;

    pdebug(DEBUG_DETAIL, "Encoded CIP path size: %d.", state->encoded_path_size);

    /* get special attributes */

    /* do we have a default payload size for the large CIP packets? */
    cip_payload_size = attr_get_int(attribs, "cip_payload", CIP_STD_PAYLOAD);
    if(cip_payload_size < 0 || cip_payload_size > 65525) {
        pdebug(DEBUG_WARN, "CIP extended payload size must be between 0 and 65535, was %d!", cip_payload_size);
        mem_free(state);
        return PLCTAG_ERR_OUT_OF_BOUNDS;
    }

    if(cip_payload_size > CIP_STD_PAYLOAD) {
        pdebug(DEBUG_INFO, "Setting CIP extended payload size to %d.", cip_payload_size);
        state->cip_payload_ex = (uint16_t)(unsigned int)cip_payload_size;
        state->cip_payload = CIP_STD_PAYLOAD;
        state->forward_open_ex_enabled = true;
    } else {
        state->cip_payload = (uint16_t)(unsigned int)cip_payload_size;
        state->forward_open_ex_enabled = false;
    }

    *result = (plc_layer_p)state;

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(plc));

    return rc;
}


/*
 * reset our state back to something sane.
 */
int cip_layer_initialize(plc_layer_p layer_arg)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_arg;

    pdebug(DEBUG_INFO, "Starting.");

    /* fill back in a few things. */
    state->base_layer.is_connected = false;

    state->cip_header_start_offset = 0;

    state->connection_id = (uint32_t)rand() & (uint32_t)0xFFFFFFFF;
    state->sequence_id = (uint16_t)rand() & 0xFFFF;

    pdebug(DEBUG_INFO, "Done.");

    return rc;
}



int cip_layer_connect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_arg;
    int offset = *payload_start;
    int max_payload_size = 0;
    int unconnected_payload_size_index = 0;
    int payload_start_index = 0;
    plc_request_id req_id_dummy = 0;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    if(state->base_layer.is_connected == true) {
        pdebug(DEBUG_INFO, "Layer is connected so reserving space.");

        /* reserve space. */
        return cip_layer_reserve_space((plc_layer_p)state, buffer, buffer_capacity, payload_start, payload_end, &req_id_dummy);
    }

    /* check with lower layers. Note that this reserves space. */
    rc = state->base_layer.next->connect(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end);
    if(rc == PLCTAG_STATUS_PENDING) {
        pdebug(DEBUG_DETAIL, "Next layer still needs to connect.");
        return rc;
    }

    /* at this point, the lower layers are connected but this layer is not. */

    /* check space */
    max_payload_size = buffer_capacity - *payload_start;
    if(max_payload_size < 92) { /* MAGIC */
        pdebug(DEBUG_WARN, "Insufficient space to build CIP connection request!");
        return PLCTAG_ERR_TOO_SMALL;
    }

    do {
        /* build a Forward Open or Forward Open Extended request. */
        pdebug(DEBUG_DETAIL, "Building Forward Open request starting at offset %d.", offset);

        /* header part. */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, 0);
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 5); /* TODO MAGIC */

        /* now the unconnected CPF (Common Packet Format) */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 2); /* two items. */

        /* first item, the address. */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0); /* Null Address Item type */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0); /* null address length = 0 */

        /* second item, the payload description */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, CPF_UNCONNECTED_DATA_ITEM);
        unconnected_payload_size_index = offset;
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0);  /* fill this in at the end */

        /* now the connection manager request. */
        payload_start_index = offset;
        if(state->forward_open_ex_enabled == true) {
            pdebug(DEBUG_DETAIL, "Forward Open extended is enabled.");
            TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_FORWARD_OPEN_REQUEST_EX);
        } else {
            pdebug(DEBUG_DETAIL, "Forward Open extended is NOT enabled.");
            TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_FORWARD_OPEN_REQUEST);
        }
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 2); /* size in words of the path. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x20); /* class, 8-bits */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x06); /* Connection Manager class */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x24); /* instance, 8-bits */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x01); /* Connection Manager, instance 1 */

        /* the actual Forward Open parameters */

        /* overall timeout parameters. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, FORWARD_OPEN_SECONDS_PER_TICK);
        TRY_SET_BYTE(buffer, buffer_capacity, offset, FORWARD_OPEN_TIMEOUT_TICKS);

        /* connection ID params. */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, 0); /* will be returned with the PLC's connection ID */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, state->connection_id); /* our connection ID */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, state->sequence_id++);   /* our connection sequence ID */

        /* identify us */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, CIP_VENDOR_ID);
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, CIP_VENDOR_SERIAL_NUMBER);

        /* timeout multiplier */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_TIMEOUT_MULTIPLIER);

        /* reserved space */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0);
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0);
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0);

        /* Our connection params */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, CIP_RPI_uS);
        if(state->forward_open_ex_enabled == true) {
            TRY_SET_U32_LE(buffer, buffer_capacity, offset, (uint32_t)CIP_CONN_PARAM_EX | (uint32_t)state->cip_payload_ex);
        } else {
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, (uint16_t)((uint16_t)CIP_CONN_PARAM | (uint16_t)state->cip_payload));
        }

        /* the PLC's connection params that we are requesting. */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, CIP_RPI_uS);
        if(state->forward_open_ex_enabled == true) {
            TRY_SET_U32_LE(buffer, buffer_capacity, offset, (uint32_t)CIP_CONN_PARAM_EX | (uint32_t)state->cip_payload_ex);
        } else {
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, (uint16_t)((uint16_t)CIP_CONN_PARAM | (uint16_t)state->cip_payload));
        }

        /* What kind of connection are we asking for?  Class 3, connected, application trigger. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_CONNECTION_TYPE);

        /* copy the encoded path */
        for(int index = 0; index < state->encoded_path_size; index++) {
            TRY_SET_BYTE(buffer, buffer_capacity, offset, state->encoded_path[index]);
        }
        if(rc != PLCTAG_STATUS_OK) {
            pdebug(DEBUG_WARN, "Error %s while copying encoded path!", plc_tag_decode_error(rc));
            break;
        }

        /* backfill the payload size. */
        pdebug(DEBUG_DETAIL, "Forward Open payload size: %d.", offset - payload_start_index);
        TRY_SET_U16_LE(buffer, buffer_capacity, unconnected_payload_size_index, offset - payload_start_index);

        pdebug(DEBUG_DETAIL, "offset=%d", offset);

        pdebug(DEBUG_INFO, "Built Forward Open request:");
        pdebug_dump_bytes(DEBUG_INFO, buffer + *payload_start, offset - *payload_start);

        /* No next payload. */
        *payload_end = offset;

        pdebug(DEBUG_DETAIL, "Set payload_start=%d and payload_end=%d.", *payload_start, *payload_end);
    } while(0);

    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Error, %s, building CIP forward open request!", plc_tag_decode_error(rc));
        return rc;
    }

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(state->plc));

    return rc;
}



int cip_layer_disconnect(plc_layer_p layer_var, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_var;
    int offset = *payload_start;
    int max_payload_size = 0;
    int payload_size_index = 0;
    int close_payload_start_index = 0;
    plc_request_id req_id = 0;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    /* if we are already disconnected, pass through. */
    if(state->base_layer.is_connected == false) {
        pdebug(DEBUG_INFO, "This layer is disconnected, passing through.");
        return state->base_layer.next->disconnect(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end);
    }

    /* this layer is not disconnected, so allocate space below. */
    rc = state->base_layer.next->reserve_space(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, &req_id);
    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Unable to allocate space in lower layers, error %s!", plc_tag_decode_error(rc));
        return rc;
    }

    /* check space */
    max_payload_size = *payload_end - *payload_start;
    if(max_payload_size < 92) { /* MAGIC */
        pdebug(DEBUG_WARN, "Insufficient space to build CIP disconnection request!");
        return PLCTAG_ERR_TOO_SMALL;
    }

    do {
        /* build a Forward Close request. */

        /* header part. */
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, 0);
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 5); /* TODO MAGIC */

        /* now the unconnected CPF (Common Packet Format) */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 2); /* two items. */

        /* first item, the address. */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0); /* Null Address Item type */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0); /* null address length = 0 */

        /* second item, the payload type and length */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, CPF_UNCONNECTED_DATA_ITEM);
        payload_size_index = offset;
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, 0); /* fill it in later. */
        close_payload_start_index = offset;

        /* now the connection manager request. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_FORWARD_CLOSE_REQUEST);
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 2); /* size in words of the path. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x20); /* class, 8-bits */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x06); /* Connection Manager class */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x24); /* instance, 8-bits */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x01); /* Connection Manager, instance 1 */

        /* overall timeout parameters. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, FORWARD_OPEN_SECONDS_PER_TICK);
        TRY_SET_BYTE(buffer, buffer_capacity, offset, FORWARD_OPEN_TIMEOUT_TICKS);

        /* connection ID params. */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, state->sequence_id++);   /* our connection sequence ID */

        /* identify us */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, CIP_VENDOR_ID);
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, CIP_VENDOR_SERIAL_NUMBER);

        /* copy the encoded path */
        for(int index = 0; index < state->encoded_path_size; index++) {
            /* there is a padding byte inserted in the path right after the length. */
            if(index == 1) {
                TRY_SET_BYTE(buffer, buffer_capacity, offset, 0);
            }

            TRY_SET_BYTE(buffer, buffer_capacity, offset, state->encoded_path[index]);
        }

        if(rc != PLCTAG_STATUS_OK) {
            pdebug(DEBUG_WARN, "Error %s while copying encoded path!", plc_tag_decode_error(rc));
            break;
        }

        /* patch up the payload size. */
        TRY_SET_U16_LE(buffer, buffer_capacity, payload_size_index, offset - close_payload_start_index);

        pdebug(DEBUG_INFO, "Build Forward Close request:");
        pdebug_dump_bytes(DEBUG_INFO, buffer + *payload_start, offset - *payload_start);

        /* There is no next payload. */
        *payload_end = offset;

        pdebug(DEBUG_INFO, "Set payload_start=%d and payload_end=%d", *payload_start, *payload_end);
    } while(0);

    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Error, %s, building CIP forward open request!", plc_tag_decode_error(rc));
        return rc;
    }

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(state->plc));

    return rc;
}


/* called bottom up. */

int cip_layer_reserve_space(plc_layer_p layer_var, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_var;
    int needed_capacity = (state->base_layer.is_connected == true ? CPF_CONNECTED_HEADER_SIZE + 2 : CPF_UNCONNECTED_HEADER_SIZE);
    int remaining_capacity = 0;

    (void)buffer;

    pdebug(DEBUG_INFO, "Starting for PLC %s with payload_start=% and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    /* reserve space in lower layers. */
    if(state->base_layer.next) {
        rc = state->base_layer.next->reserve_space(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
        if(rc != PLCTAG_STATUS_OK) {
            pdebug(DEBUG_WARN, "Error %s returned while reserving space in lower layers!", plc_tag_decode_error(rc));
            return rc;
        }
    } else {
        pdebug(DEBUG_DETAIL, "No lower layers.");
    }

    /* allocate space for the CIP header. */
    remaining_capacity = buffer_capacity - *payload_start;
    if(remaining_capacity < needed_capacity) {
        pdebug(DEBUG_WARN, "Buffer size, (%d) is too small for CIP CPF header (size %d)!", remaining_capacity, needed_capacity);
        return PLCTAG_ERR_TOO_SMALL;
    }

    state->cip_header_start_offset = *payload_start;

    /* bump the start index past the header.  Start for the next layer. */
    *payload_start = *payload_start + needed_capacity;

    /* where could the CIP payload end? */
    if(state->forward_open_ex_enabled == true) {
        *payload_end = state->cip_payload_ex + CIP_PAYLOAD_HEADER_FUDGE;
    } else {
        *payload_end = state->cip_payload + CIP_PAYLOAD_HEADER_FUDGE;
    }

    /* clamp payload_end to the end of the buffer size. */
    if(*payload_end > buffer_capacity) {
        /* clamp it. */
        pdebug(DEBUG_DETAIL, "Clamping payload end to %d from %d.", buffer_capacity, *payload_end);
        *payload_end = buffer_capacity;
    }

    if(*payload_start > *payload_end) {
        pdebug(DEBUG_WARN, "Not enough data in the buffer for a payload!");
        return PLCTAG_ERR_TOO_SMALL;
    }

    pdebug(DEBUG_INFO, "Done for PLC %s with payload_start=% and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    return rc;
}



/* called top down. */

int cip_layer_build_layer(plc_layer_p layer_var, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_var;
    int offset = state->cip_header_start_offset;
    int payload_size = *payload_end - *payload_start;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    /* check to see if we are connected or not. */
    if(state->base_layer.is_connected) {
        /* build CPF header. */
        do {
            if(payload_size <= 2) {  /* MAGIC - leave space for the sequence ID */
                pdebug(DEBUG_WARN, "Insufficient space for payload!");
                rc = PLCTAG_ERR_TOO_SMALL;
                break;
            }

            /* header part. */
            TRY_SET_U32_LE(buffer, buffer_capacity, offset, 0);
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, 5); /* TODO MAGIC */

            /* now the connected CPF (Common Packet Format) */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, 2); /* two items. */

            /* first item, the connected address. */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, CPF_CONNECTED_ADDRESS_ITEM); /* Null Address Item type */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, 4); /* address length = 4 bytes */
            TRY_SET_U32_LE(buffer, buffer_capacity, offset, state->plc_connection_id);

            /* second item, the data item and size */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, CPF_CONNECTED_DATA_ITEM); /* Null Address Item type */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, payload_size + 2); /* data length, note includes the sequence ID below! */

            /* this is not considered part of the header but part of the payload for size calculation... */

            /* set the connection sequence id */
            TRY_SET_U16_LE(buffer, buffer_capacity, offset, state->sequence_id++);

            /* check */
            if(offset != *payload_start) {
                pdebug(DEBUG_WARN, "Header ends at %d but payload starts at %d!", offset, *payload_start);
                rc = PLCTAG_ERR_BAD_CONFIG;
                break;
            }

            /* move the start backward to the start of this header. */
            *payload_start = state->cip_header_start_offset;

            pdebug(DEBUG_INFO, "Built CIP CPF packet:");
            pdebug_dump_bytes(DEBUG_INFO, buffer + *payload_start, *payload_end - *payload_start);

            pdebug(DEBUG_INFO, "Set payload_start=%d and payload_end=%d.", *payload_start, *payload_end);
        } while(0);
    } else {
        pdebug(DEBUG_DETAIL, "This layer is not yet connected, skipping request build.");
    }

    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Unable to build CIP header packet, error %s!", plc_tag_decode_error(rc));
        return rc;
    }

    if(state->base_layer.next) {
        pdebug(DEBUG_DETAIL, "Passing through to next layer.");
        rc = state->base_layer.next->build_layer(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
    } else {
        pdebug(DEBUG_DETAIL, "No more layers.");
    }

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(state->plc));

    return rc;
}


int cip_layer_process_response(plc_layer_p layer_var, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_var;
    int offset = *payload_start;
    int payload_size = 0;
    int min_decode_size = (state->base_layer.is_connected == true ? CPF_CONNECTED_HEADER_SIZE : CPF_UNCONNECTED_HEADER_SIZE);

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    if(state->base_layer.next) {
        pdebug(DEBUG_DETAIL, "Passing through to next layer.");
        rc = state->base_layer.next->process_response(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
        if(rc != PLCTAG_STATUS_OK) {
            pdebug(DEBUG_INFO, "Next layer process_response function returned %s.", plc_tag_decode_error(rc));
            return rc;
        }
    } else {
        pdebug(DEBUG_DETAIL, "No more layers.");
    }

    /* there is only one CIP response in a packet. */
    *req_id = 1;

    /* we at least have the header */
    do {
        payload_size = *payload_end - *payload_start;
        if(payload_size < min_decode_size) {
            pdebug(DEBUG_DETAIL, "Amount of data is insufficient to decode CPF header.");
            rc = PLCTAG_ERR_PARTIAL;
            break;
        }

        /* we have enough to decode the CPF header, which kind is it? */
        if(state->base_layer.is_connected == false) {
            uint32_t dummy_u32;
            uint16_t dummy_u16;
            uint16_t cpf_payload_size = 0;
            uint8_t cip_service_code = 0;

            /* get the interface handle and router timeout, discard */
            TRY_GET_U32_LE(buffer, buffer_capacity, offset, dummy_u32);
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, dummy_u16);

            /* get the CPF header */
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, dummy_u16); /* item count */
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, dummy_u16); /* null address item */
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, dummy_u16); /* null address size */
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, dummy_u16); /* unconnected data item */
            TRY_GET_U16_LE(buffer, buffer_capacity, offset, cpf_payload_size); /* payload size */

            pdebug(DEBUG_INFO, "CIP unconnected payload size: %d.", (int)(unsigned int)cpf_payload_size);

            /* we might have a Forward Open reply */
            if(cpf_payload_size < 4) {
                pdebug(DEBUG_WARN, "Malformed CIP response packet.");
                rc = PLCTAG_ERR_BAD_REPLY;
                break;
            }

            /* don't destructively get this as we might not handle it. */
            cip_service_code = buffer[offset];

            *payload_start = offset;

            if(cip_service_code == (CIP_FORWARD_OPEN_REQUEST | CIP_CMD_EXECUTED_FLAG) || cip_service_code == (CIP_FORWARD_OPEN_REQUEST_EX | CIP_CMD_EXECUTED_FLAG)) {
                rc = process_forward_open_response(state, buffer, buffer_capacity, payload_start, payload_end);
                break;
            } else if(cip_service_code == (CIP_FORWARD_CLOSE_REQUEST | CIP_CMD_EXECUTED_FLAG)) {
                rc = process_forward_close_response(state, buffer, buffer_capacity, payload_start, payload_end);
                break;
            } else {
                pdebug(DEBUG_WARN, "Unexpected UCMM response!");

                /* not our packet */
                *payload_start = *payload_start + CPF_UNCONNECTED_HEADER_SIZE;
                break;
            }
        } else {
            /* We do not process connected responses. */
            *payload_start = *payload_start + CPF_CONNECTED_HEADER_SIZE + 2;
        }

        pdebug(DEBUG_INFO, "Set payload_start=%d and payload_end=%d.", *payload_start, *payload_end);
    } while(0);

    if(rc != PLCTAG_STATUS_OK && rc != PLCTAG_ERR_PARTIAL) {
        if(rc == PLCTAG_STATUS_PENDING) {
            pdebug(DEBUG_INFO, "CIP response had a problem, retrying.");
        } else {
            pdebug(DEBUG_WARN, "Unable to process CIP header packet, error %s!", plc_tag_decode_error(rc));
        }

        return rc;
    }


    pdebug(DEBUG_INFO, "Done.");

    return rc;
}




int cip_layer_destroy_layer(plc_layer_p layer_var)
{
    int rc = PLCTAG_STATUS_OK;
    struct cip_layer_s *state = (struct cip_layer_s *)layer_var;

    pdebug(DEBUG_INFO, "Cleaning up CIP layer.");

    if(state) {
        if(state->base_layer.next) {
            pdebug(DEBUG_INFO, "Destroying next layer.");
            state->base_layer.next->destroy_layer(state->base_layer.next);
            state->base_layer.next = NULL;
        }

        mem_free(state);
    }

    pdebug(DEBUG_INFO, "Done.");

    return rc;
}





int process_forward_open_response(struct cip_layer_s *state,uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    int rc = PLCTAG_STATUS_OK;

    do {
        uint8_t dummy_u8;
        uint8_t status;
        uint8_t status_size;

        /* it is a response to Forward Open, one of them at least. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), dummy_u8); /* service code. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), dummy_u8); /* reserved byte. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), status); /* status byte. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), status_size); /* extended status size in 16-bit words. */

        if(dummy_u8 != 0) {
            pdebug(DEBUG_DETAIL, "Reserved byte is not zero!");
        }

        if(status == CIP_SERVICE_STATUS_OK) {
            pdebug(DEBUG_INFO, "Processing successful Forward Open response:");
            pdebug_dump_bytes(DEBUG_INFO, buffer + *payload_start, *payload_end - *payload_start);

            /* get the target PLC's connection ID and save it. */
            TRY_GET_U32_LE(buffer, buffer_capacity, (*payload_start), state->plc_connection_id);

            pdebug(DEBUG_INFO, "Using connection ID %" PRIx32 " for PLC connection ID.", state->plc_connection_id);

            /* TODO - decode some of the rest of the packet, might be useful. */

            /* make sure PLC has sufficient buffer. */
            rc = plc_set_buffer_size(state->plc, CIP_PAYLOAD_HEADER_FUDGE + (state->forward_open_ex_enabled ? state->cip_payload_ex : state->cip_payload));
            if(rc != PLCTAG_STATUS_OK) {
                pdebug(DEBUG_WARN, "Unable to set PLC buffer, error %s!", plc_tag_decode_error(rc));
                break;
            }

            *payload_start = *payload_end;

            state->base_layer.is_connected = true;

            rc = PLCTAG_STATUS_OK;
            break;
        } else {
            pdebug(DEBUG_INFO, "Processing UNSUCCESSFUL Forward Open response:");
            pdebug_dump_bytes(DEBUG_INFO, buffer + *payload_start, *payload_end - *payload_start);

            /* Oops, now check to see what to do. */
            if(status == 0x01 && status_size >= 2) {
                uint16_t extended_status;

                /* we might have an error that tells us the actual size to use. */
                TRY_GET_U16_LE(buffer, buffer_capacity, (*payload_start), extended_status);

                if(extended_status == 0x109) { /* MAGIC */
                    uint16_t supported_size = 0;

                    TRY_GET_U16_LE(buffer, buffer_capacity, (*payload_start), supported_size);

                    pdebug(DEBUG_INFO, "Error from Forward Open request, unsupported size, but size %u is supported.", (unsigned int)supported_size);

                    if(state->forward_open_ex_enabled == true) {
                        state->cip_payload_ex = supported_size;
                    } else {
                        if(supported_size > 0x1F8) {
                            pdebug(DEBUG_INFO, "Supported size is greater than will fit into 9 bits.  Clamping to 0x1f8.");
                            supported_size = 0x1F8; /* MAGIC default for small CIP packets. */
                        }

                        state->cip_payload = supported_size;
                    }

                    /* retry */
                    rc = PLCTAG_STATUS_RETRY;
                    break;
                } else if(extended_status == 0x100) { /* MAGIC */
                    pdebug(DEBUG_INFO, "Error from Forward Open request, duplicate connection ID.  Need to try again.");
                    /* retry */
                    rc = PLCTAG_STATUS_RETRY;
                    break;
                } else {
                    pdebug(DEBUG_WARN, "CIP error %s (%s)!", cip_decode_error_short(status, extended_status), cip_decode_error_long(status, extended_status));
                    pdebug(DEBUG_WARN, "CIP error %x (extended error %x)!", (unsigned int)status, (unsigned int)extended_status);
                    rc = PLCTAG_ERR_REMOTE_ERR;
                    break;
                }
            } else if(status == CIP_ERR_UNSUPPORTED) {
                if(state->forward_open_ex_enabled == true) {
                    /* we do not support extended forward open. */

                    pdebug(DEBUG_INFO, "Forward Open Extended request is not supported, trying old Forward Open.");

                    state->forward_open_ex_enabled = false;
                    rc = PLCTAG_STATUS_RETRY;
                    break;
                } else {
                    pdebug(DEBUG_WARN, "CIP error, Forward Open is unsupported!");
                    break;
                }
            } else if(status == CIP_ERR_NO_RESOURCES) {
                if(state->forward_open_ex_enabled == true) {
                    /* try a smaller size */
                    if(state->cip_payload_ex > CIP_STD_EX_PAYLOAD) {
                        pdebug(DEBUG_INFO, "Original payload size of %u is too large trying %d.", (unsigned int)(state->cip_payload_ex), CIP_STD_EX_PAYLOAD);
                        state->cip_payload_ex = CIP_STD_EX_PAYLOAD;
                        rc = PLCTAG_STATUS_RETRY;
                        break;
                    } else if(state->cip_payload_ex > CIP_STD_PAYLOAD) {
                        pdebug(DEBUG_INFO, "Original payload size of %u is too large trying %d.", (unsigned int)(state->cip_payload_ex), CIP_STD_PAYLOAD);
                        state->cip_payload_ex = CIP_STD_PAYLOAD;
                        rc = PLCTAG_STATUS_RETRY;
                        break;
                    } else {
                        /* we do not support extended forward open. */
                        state->forward_open_ex_enabled = false;

                        if(state->cip_payload == 0) {
                            state->cip_payload = CIP_STD_PAYLOAD;
                        }

                        rc = PLCTAG_STATUS_RETRY;
                        break;
                    }
                } else {
                    rc = cip_decode_error_code(status, 0);
                    pdebug(DEBUG_WARN, "Error %s returned in CIP forward open response!", cip_decode_error_short(status, 0));
                    break;
                }
            } else {
                pdebug(DEBUG_WARN, "CIP error code %s (%s)!", cip_decode_error_short(status, 0), cip_decode_error_long(status, 0));
                rc = PLCTAG_ERR_REMOTE_ERR;
                break;
            }
        }
    } while(0);

    pdebug(DEBUG_DETAIL, "Done.");

    return rc;
}


int process_forward_close_response(struct cip_layer_s *state,uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    int rc = PLCTAG_STATUS_OK;

    pdebug(DEBUG_DETAIL, "Starting with payload:");
    pdebug_dump_bytes(DEBUG_DETAIL, buffer + *payload_start, *payload_end - *payload_start);

    do {
        uint8_t dummy_u8;
        uint8_t status;
        uint8_t status_size;

        /* regardless of the status, we are disconnected. */
        state->base_layer.is_connected = false;

        /* it is a response to Forward Close. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), dummy_u8); /* service code. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), dummy_u8); /* reserved byte. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), status); /* status byte. */
        TRY_GET_BYTE(buffer, buffer_capacity, (*payload_start), status_size); /* extended status size in 16-bit words. */

        if(dummy_u8 != 0) {
            pdebug(DEBUG_DETAIL, "Reserved byte is not zero!");
        }

        if(status == CIP_SERVICE_STATUS_OK) {
            /* TODO - decode some of the payload. */
            *payload_start = *payload_end;

            rc = PLCTAG_STATUS_OK;
            break;
        } else {
            /* Oops, now check to see what to do. */
            if(status == 0x01 && status_size >= 2) {
                uint16_t extended_status;

                /* Get the extended error */
                TRY_GET_U16_LE(buffer, buffer_capacity, (*payload_start), extended_status);

                pdebug(DEBUG_WARN, "CIP error %x (extended error %x)!", (unsigned int)status, (unsigned int)extended_status);
                rc = PLCTAG_ERR_REMOTE_ERR;
                break;
            } else {
                pdebug(DEBUG_WARN, "CIP error %x!", (unsigned int)status);
                rc = PLCTAG_ERR_REMOTE_ERR;
                break;
            }
        }
    } while(0);


    pdebug(DEBUG_DETAIL, "Done.");

    return rc;
}



