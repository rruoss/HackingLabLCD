# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-039.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
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
tag_summary = "The ISA Server 2000 and Proxy Server 2.0 have been found to be vulnerable to
a spoofing vulnerability that could enable an attacker to spoof trusted Internet 
content. Users could believe they are accessing trusted Internet content when 
in reality they are accessing malicious Internet content, for example a 
malicious Web site. However, an attacker would first have to persuade a user to 
visit the attacker's to attempt to exploit this vulnerability.

See http://www.microsoft.com/technet/security/bulletin/ms04-039.mspx";

if(description)
{
 script_id(15714);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2004-0892");
 
 name = "ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for hotfix Q888258";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Jeff Adams");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
if(!fix)security_hole(port);
