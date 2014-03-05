# OpenVAS Vulnerability Test
# $Id: dump.inc 10794 2011-04-17 18:15:31Z jan $
# Description: Some support functions for dump
#
# Authors:
# Tenable Network Security
# An earlier iteration of this file was written by George Dagousset (2002)
#
# Copyright:
# Copyright (C) 2004 Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

function line2string (line, linenumber)
{
 local_var tmp, pos;

 line = line*16;
 tmp = raw_string (
	(line >> 24) & 0xFF,
	(line >> 16) & 0xFF,
	(line >> 8) & 0xFF,
	(line ) & 0xFF
	);

 if (linenumber < 256)
   pos = 3;
 else if (linenumber < 65536)
   pos = 2;
 else if (linenumber < 16777216)
   pos = 1;
 else
   pos = 0;

 return string ("0x", toupper(hexstr(substr (tmp, pos, 3))), ": ");
}


function isprint (c)
{
 if ( (ord(c) >= 0x20) && (ord(c) <= 0x7E) )
   return TRUE;

 return FALSE;
}


function hexdump (ddata)
{
 local_var tmp, i, j, line, linenumber, len, data, c;

 len = strlen (ddata);
 linenumber = len / 16;

 for (i = 0; i <= linenumber; i++)
 {
  line = line2string (line:i, linenumber:len);
  data = "";

  for (j = 0; j < 16; j++)
  {
   if ( (i*16+j) < len )
   {
    line += string (" ", toupper (hexstr(ddata[i*16+j])) );

    c = ddata[i*16+j];

    if (isprint (c:c))
      data += c;
    else
      data += ".";
   }
   else
   {
    line += "   ";
    data += " ";
   }
  }

  tmp += string (line, "    ", data, "\n");
 }

 return tmp;
}
 

function dump( dtitle, ddata )
{
 if( ! isnull( dtitle ) )
	display('---[ ' + dtitle + ' ]---\n' );


 display(hexdump(ddata:ddata));
}

