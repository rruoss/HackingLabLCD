# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-009.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IE VBScript Handling patch (Q318089)
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
tag_summary = "Incorrect VBScript Handling in IE can Allow Web 
Pages to Read Local Files.

Impact of vulnerability: Information Disclosure

Affected Software: 

Microsoft Internet Explorer 5.01
Microsoft Internet Explorer 5.5 
Microsoft Internet Explorer 6.0 

See
http://www.microsoft.com/technet/security/bulletin/ms02-009.mspx
and: Microsoft Article
Q319847 MS02-009 May Cause Incompatibility Problems Between
 VBScript and Third-Party Applications";

if(description)
{
 script_id(10926);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4158);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-0052");
 name = "IE VBScript Handling patch (Q318089)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Determines whether the IE VBScript Handling patch (Q318089) is installed";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/WinXP/ServicePack");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("secpod_reg.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{4f645220-306d-11d2-995d-00c04f98bbc9}/Version");
if (!key) exit (0);


if(ereg(pattern:"^([1-4],.*|5,([0-5],.*|6,0,([0-9]?[0-9]?[0-9]$|[0-6][0-9][0-9][0-9]|7([0-3]|4([01]|2[0-5])))))", string:key))
{ 
  security_warning(port);
  exit(0);
}
