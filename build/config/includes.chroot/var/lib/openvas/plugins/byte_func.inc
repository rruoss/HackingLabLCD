###############################################################################
# $Id: byte_func.inc 5627 2009-10-19 16:54:42Z mime $
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

global_var BYTE_ORDER;

# Little-endian byte order 
BYTE_ORDER_LITTLE_ENDIAN = 1;
# Big-endian byte order
BYTE_ORDER_BIG_ENDIAN    = 2;
# Set default
BYTE_ORDER = BYTE_ORDER_BIG_ENDIAN;

function mkword() {
  local_var value,DATA;

  if(isnull(_FCT_ANON_ARGS[0])) {
     return 0;
  }
  value = _FCT_ANON_ARGS[0];
  if (BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN) {
    DATA = raw_string((value >> 8) & 255, value & 255);
  } else {
    DATA = raw_string(value & 255, (value >> 8) & 255);
  }  
 return DATA;
}

function set_byte_order() {
  if(!isnull(_FCT_ANON_ARGS[0])) {
    if(_FCT_ANON_ARGS[0] == BYTE_ORDER_BIG_ENDIAN || _FCT_ANON_ARGS[0] == BYTE_ORDER_LITTLE_ENDIAN) {
      BYTE_ORDER = _FCT_ANON_ARGS[0];
    }  
  }   
}

function mkdword() {
 local_var value,DATA;

 if(isnull(_FCT_ANON_ARGS[0])) {
  return 0;
 }

 value = _FCT_ANON_ARGS[0];

 if(BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN) {
    DATA =  raw_string((value >> 24) & 255, (value >> 16) & 255, (value >>  8) & 255, (value) & 255);
 } else {
    DATA =  raw_string(value & 255, (value >> 8) & 255, (value >> 16) & 255, (value >> 24) & 255);
 }
 return DATA;
}

function mkpad() {
 local_var length,DATA;
 if(isnull(_FCT_ANON_ARGS[0])) {
  length = 1000;
 } else {
  length = _FCT_ANON_ARGS[0];
 }
 DATA = crap(data:raw_string(0x00), length:length);
 return DATA;
}

function getword(blob,pos) {
 local_var value,DATA;

 if(!blob = substr(blob,pos))return 0;

 if(BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN) {
  DATA = ord(blob[0]) << 8 | ord(blob[1]);
 } else {
  DATA = ord(blob[0]) | ord(blob[1]) << 8;
 }
 return DATA;
}

function getdword(blob,pos) {
 local_var value,DATA;

 if(!blob = substr(blob,pos))return 0;

 if (BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN) {
  DATA = ord(blob[0]) << 24 | ord(blob[1]) << 16 | ord(blob[2]) << 8 | ord(blob[3]);
 }  else {
  DATA = ord(blob[0]) | ord(blob[1]) << 8 | ord(blob[2]) << 16 | ord(blob[3]) << 24;
 }
return DATA;
}

function dec2bin(dec) {

  local_var dnum, res;

  dnum = int(dec);

  if(dnum == 0)
    return dnum;

  while (dnum > 0) {
    res = string(dnum & 1) + res;
    dnum = dnum >>= 1;
  }

  while(strlen(res) < 8) {
    res = string(0) + res;
  }

  return res;

}

