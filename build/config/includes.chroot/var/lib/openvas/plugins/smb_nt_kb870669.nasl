# OpenVAS Vulnerability Test
# $Id: smb_nt_kb870669.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ADODB.Stream object from Internet Explorer (KB870669)
#
# Authors:
# Noam Rathaus noamr@beyondsecurity.com
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

include("revisions-lib.inc");
tag_summary = "An ADO stream object represents a file in memory.  The stream object contains 
several methods for reading and writing binary files and text files. 
When this by-design functionality is combined with known security 
vulnerabilities in Microsoft Internet Explorer, an Internet Web site could
execute script from the Local Machine zone.

This behavior occurs because the ADODB.Stream object permits
access to the hard disk when the ADODB.Stream object is hosted
in Internet Explorer.";

tag_solution = "http://support.microsoft.com/?kbid=870669";

if(description)
{
 script_id(12298);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10514);
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "ADODB.Stream object from Internet Explorer (KB870669)";

 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for KB870669";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("secpod_reg.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags");

if ( value && value != 1024  && hotfix_missing(name:"870669") )
   security_hole(port);
