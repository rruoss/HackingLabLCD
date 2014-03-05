###############################################################################
# Functions for LDAP
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA.
###############################################################################

function ldap_alive(port)
{

   local_var  req, buf, response;

   req = raw_string(0x30,0x84,0x00,0x00,0x00,0x59,0x02,0x01,0x05,0x63,0x84,0x00,
                    0x00,0x00,0x50,0x04,0x13,0x64,0x63,0x3d,0x6f,0x70,0x65,0x6e,
                    0x76,0x61,0x73,0x64,0x63,0x2c,0x64,0x63,0x3d,0x6e,0x65,0x74,
                    0x0a,0x01,0x02,0x0a,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00,
                    0x01,0x01,0x00,0xa3,0x84,0x00,0x00,0x00,0x13,0x04,0x0b,0x6f,
                    0x62,0x6a,0x65,0x63,0x74,0x43,0x6c,0x61,0x73,0x73,0x04,0x04,
                    0x75,0x73,0x65,0x72,0x30,0x84,0x00,0x00,0x00,0x0d,0x04,0x0b,
                    0x64,0x69,0x73,0x70,0x6c,0x61,0x79,0x4e,0x61,0x6d,0x65);  

   soc = open_sock_tcp(port);
   if(!soc)return NULL;

   send(socket:soc, data:req);
   buf = recv(socket:soc, length:1);
   if( buf == NULL )return NULL;
   close(soc);

   if(strlen(buf) == 1) {
     response = hexstr(buf);
     if(response =~ "^30$" )return TRUE;
   }
 return NULL;
}

# extract the message length
# WARNING offset is updated by the function call (reference) !
function get_ber_size(buf, offset) {
    local_var lm_length, length_length, i;
    lm_length = ord(buf[offset]);
    offset++;
    if(lm_length > 128) {
        # undetermined length message
        length_length = lm_length - 128;
        lm_length = 0;
        for(i=0; i<length_length; i++) {
            lm_length = (lm_length << 8) | ord(buf[offset++]);
        }
    }
    return lm_length;
}

function is_ldapv3(port) {
    local_var offset, lm_length, messageId_length, bindResponse_length, resultCode_length, resultCode, i, soc, buf;

    soc = open_sock_tcp(port);
    if(!soc) return FALSE;

    req =  raw_string(0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00); # v3 bind
    send(socket:soc, data:req);

    buf = recv(socket:soc, length:128);
    close(soc);

    if(!buf) return FALSE;

    # decode ldapMessage length (encoded as BER)
    offset = 0;
    if(ord(buf[offset++]) != 48) return FALSE; # (0x30)
    lm_length = get_ber_size(buf, offset);
    if (strlen(buf) < lm_length + offset) return FALSE; # whoops, we have not enough data (should never happen since bindResponse is a short message)

    # we are not at offset = message id, we skip it
    if (ord(buf[offset++]) != 2) return FALSE; # messageId is an INT
    messageId_length = get_ber_size(buf, offset);
    offset += messageId_length;

    # now enter the bindResponse
    if (ord(buf[offset++]) != 97) return FALSE; # (0x61)
    bindResponse_length = get_ber_size(buf, offset);

    # now dig into response code
    if (ord(buf[offset++]) != 10) return FALSE; # (0x0A)
    resultCode_length = get_ber_size(buf, offset);
    resultCode = 0;
    for (i=0; i<resultCode_length; i++) {
        resultCode = (resultCode << 8) | ord(buf[offset++]);
    }
    if (resultCode == 0) return TRUE; # server has accepted the v3 bind

    return FALSE;
}  
