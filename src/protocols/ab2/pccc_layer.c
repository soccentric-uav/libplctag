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

#include <stdlib.h>
#include <ab2/cip_layer.h>
#include <ab2/df1.h>
#include <ab2/pccc_layer.h>
#include <lib/libplctag.h>
#include <util/atomic_int.h>
#include <util/attr.h>
#include <util/mem.h>
#include <util/mutex.h>
#include <util/plc.h>
#include <util/socket.h>
#include <util/string.h>


#define CIP_PCCC_CMD ((uint8_t)0x4B)
#define CIP_CMD_OK ((uint8_t)0x80)

#define PCCC_REQ_HEADER_SIZE (13)
#define PCCC_RESP_HEADER_SIZE (11)

struct pccc_layer_state_s {
    struct plc_layer_s base_layer;

    plc_p plc;

    int pccc_header_start_offset;
};


static int pccc_layer_initialize(plc_layer_p layer_arg);
static int pccc_layer_connect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);
static int pccc_layer_disconnect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end);
static int pccc_layer_reserve_space(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int pccc_layer_build_layer(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int pccc_layer_process_response(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id);
static int pccc_layer_destroy_layer(plc_layer_p layer_arg);




int pccc_layer_setup(plc_p plc, attr attribs, plc_layer_p *result)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = NULL;

    (void)attribs;

    pdebug(DEBUG_INFO, "Starting.");

    state = mem_alloc(sizeof(*state));
    if(!state) {
        pdebug(DEBUG_WARN, "Unable to allocate EIP layer state!");
        return PLCTAG_ERR_NO_MEM;
    }

    state->plc = plc;

    state->base_layer.initialize = pccc_layer_initialize;
    state->base_layer.connect = pccc_layer_connect;
    state->base_layer.disconnect = pccc_layer_disconnect;
    state->base_layer.reserve_space = pccc_layer_reserve_space;
    state->base_layer.build_layer = pccc_layer_build_layer;
    state->base_layer.process_response = pccc_layer_process_response;
    state->base_layer.destroy_layer = pccc_layer_destroy_layer;

    *result = (plc_layer_p)state;

    pdebug(DEBUG_INFO, "Done.");

    return rc;
}


/*
 * reset our state back to something sane.
 */
int pccc_layer_initialize(plc_layer_p layer_arg)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;

    (void)state;

    pdebug(DEBUG_INFO, "Initializing EIP layer.");

    pdebug(DEBUG_INFO, "Done.");

    return rc;
}



int pccc_layer_connect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(state->plc));

    return state->base_layer.next->connect(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end);
}






int pccc_layer_disconnect(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end)
{
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    pdebug(DEBUG_INFO, "Done for PLC %s.", plc_get_key(state->plc));

    return state->base_layer.next->disconnect(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end);
}



/* called bottom up */

int pccc_layer_reserve_space(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;
    int max_payload_size = 0;

    pdebug(DEBUG_INFO, "Starting for PLC %s.", plc_get_key(state->plc));

    rc = state->base_layer.next->reserve_space(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Unable to reserve space in the next layer, error %s!", plc_tag_decode_error(rc));
        return rc;
    }

    /* allocate space for the PCCC header. */
    max_payload_size = *payload_end - *payload_start;
    if(max_payload_size < PCCC_REQ_HEADER_SIZE) {
        pdebug(DEBUG_WARN, "Buffer size, (%d) is too small for EIP header (size %d)!", buffer_capacity, PCCC_REQ_HEADER_SIZE);
        return PLCTAG_ERR_TOO_SMALL;
    }

    /* store the payload start for the header. */
    state->pccc_header_start_offset = *payload_start;

    /* bump the start for the next payload. */
    *payload_start += PCCC_REQ_HEADER_SIZE;

    /* FIXME - need to set the payload end here. */

    pdebug(DEBUG_INFO, "Done PLC %s with payload_start=%d and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    return rc;
}



int pccc_layer_build_layer(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;
    int offset = state->pccc_header_start_offset;

    pdebug(DEBUG_INFO, "Starting for PLC %s with payload_start=%d and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    do {
        /* check the start against our header size. */
        if(*payload_start - PCCC_REQ_HEADER_SIZE != state->pccc_header_start_offset) {
            pdebug(DEBUG_WARN, "Unexpected offsets.  Payload start less the header size, %d, is not equal to the saved header start, %d!", *payload_start - PCCC_REQ_HEADER_SIZE, state->pccc_header_start_offset);
            rc = PLCTAG_ERR_BAD_CONFIG;
            break;
        }

        /* put in the PCCC CIP command */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, CIP_PCCC_CMD);

        /* now put in the route to the object. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 2); /* route is two words long, 4 bytes. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x20); /* class, 8-bit id */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x67); /* PCCC class, 8-bit id */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x24); /* instance, 8-bit id */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 0x01); /* PCCC class instance 1, 8-bit id */

        /* an identifier for this request of who we are. */
        TRY_SET_BYTE(buffer, buffer_capacity, offset, 7); /* identifier is 7 bytes long. */
        TRY_SET_U16_LE(buffer, buffer_capacity, offset, CIP_VENDOR_ID);
        TRY_SET_U32_LE(buffer, buffer_capacity, offset, CIP_VENDOR_SERIAL_NUMBER);

        if(offset != *payload_start) {
            pdebug(DEBUG_WARN, "The offset after building the header, %d, is not equal start of the next layer up, %d!", offset, *payload_start);
            rc = PLCTAG_ERR_BAD_CONFIG;
            break;
        }

        /* move the start backward for the next layer down. */
        *payload_start = state->pccc_header_start_offset;

        pdebug(DEBUG_DETAIL, "Build PCCC packet:");
        pdebug_dump_bytes(DEBUG_DETAIL, buffer + *payload_start, *payload_end - *payload_start);

        pdebug(DEBUG_INFO, "Set payload_start=%d and payload_end=%d.", *payload_start, *payload_end);

        /* call down into the next layer. */
        rc = state->base_layer.next->build_layer(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
    } while(0);

    if(rc != PLCTAG_STATUS_OK) {
        pdebug(DEBUG_WARN, "Unable to build PCCC header packet, error %s!", plc_tag_decode_error(rc));
        return rc;
    }

    pdebug(DEBUG_INFO, "Done for PLC %s with payload_start=%d and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    return rc;
}


/* bottom up. */

int pccc_layer_process_response(plc_layer_p layer_arg, uint8_t *buffer, int buffer_capacity, int *payload_start, int *payload_end, plc_request_id *req_id)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;
    int offset = *payload_start;

    pdebug(DEBUG_INFO, "Starting for PLC %s with payload_start=%d and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);


    do {
        uint8_t cip_service_code = 0;
        uint8_t dummy_u8 = 0;
        uint8_t status = 0;
        uint8_t extended_status_words = 0;

        /* call down to next layer. */
        rc = state->base_layer.next->process_response(state->base_layer.next, buffer, buffer_capacity, payload_start, payload_end, req_id);
        if(rc != PLCTAG_STATUS_OK) {
            if(rc == PLCTAG_ERR_PARTIAL) {
                pdebug(DEBUG_INFO, "Full packet not yet received, continue to wait.");
                break;
            } else {
                pdebug(DEBUG_WARN, "Error %s in lower layers processing response!", plc_tag_decode_error(rc));
                break;
            }
        }

        TRY_GET_BYTE(buffer, buffer_capacity, offset, cip_service_code);
        TRY_GET_BYTE(buffer, buffer_capacity, offset, dummy_u8);
        TRY_GET_BYTE(buffer, buffer_capacity, offset, status);
        TRY_GET_BYTE(buffer, buffer_capacity, offset, extended_status_words);

        if(dummy_u8 != 0) {
            pdebug(DEBUG_INFO, "Reserved byte is not zero!");
        }

        if(cip_service_code != (CIP_CMD_OK | CIP_PCCC_CMD)) {
            pdebug(DEBUG_WARN, "Unexpected CIP service %x!", (unsigned int)cip_service_code);
            rc = PLCTAG_ERR_BAD_REPLY;
            break;
        }

        if(status == 0) {
            /* all good. */
            *payload_start += PCCC_RESP_HEADER_SIZE;

            pdebug(DEBUG_INFO, "Set payload_start=%d and payload_end=%d.", *payload_start, *payload_end);

            break;
        } else {
            /* error! */
            if(extended_status_words > 0) {
                uint16_t extended_status;

                TRY_GET_U16_LE(buffer, buffer_capacity, offset, extended_status);

                pdebug(DEBUG_WARN, "CIP error %x (extended status %x)!", (unsigned int)status, (unsigned int)extended_status);
            } else {
                pdebug(DEBUG_WARN, "CIP error %x!", (unsigned int)status);
            }

            rc = PLCTAG_ERR_BAD_STATUS;
            break;
        }
    } while(0);

    if(rc != PLCTAG_STATUS_OK && rc != PLCTAG_ERR_PARTIAL) {
        pdebug(DEBUG_WARN, "Unable to process PCCC header packet, error %s!", plc_tag_decode_error(rc));
        return rc;
    }

    pdebug(DEBUG_INFO, "Done for PLC %s with payload_start=%d and payload_end=%d.", plc_get_key(state->plc), *payload_start, *payload_end);

    return rc;
}



int pccc_layer_destroy_layer(plc_layer_p layer_arg)
{
    int rc = PLCTAG_STATUS_OK;
    struct pccc_layer_state_s *state = (struct pccc_layer_state_s *)layer_arg;

    pdebug(DEBUG_INFO, "Cleaning up PCCC layer.");

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

