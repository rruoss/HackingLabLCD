# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-017.nasl 17 2013-10-27 14:01:43Z jan $
# Description: MUP overlong request kernel overflow Patch (Q311967)
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
tag_summary = "Buffer overflow in Multiple UNC Provider (MUP) in Microsoft
Windows operating systems allows local users to cause a
denial of service or possibly gain SYSTEM privileges via a
long UNC request. 

Affected Software: 

Microsoft Windows NT 4.0 Workstation 
Microsoft Windows NT 4.0 Server 
Microsoft Windows NT 4.0 Server, Enterprise Edition 
Microsoft Windows NT 4 Terminal Server Edition 
Microsoft Windows 2000 Professional 
Microsoft Windows 2000 Server 
Microsoft Windows 2000 Advanced Server 
Microsoft Windows XP Professional 

See
http://www.microsoft.com/technet/security/bulletin/ms02-017.mspx";

if(description)
{
 script_id(10944);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4426);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0151");
 name = "MUP overlong request kernel overflow Patch (Q311967)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "checks for Multiple UNC Provider Patch (Q311967)";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0); 
if ( hotfix_missing(name:"Q312895") > 0  ) 
	security_hole(get_kb_item("SMB/transport"));

