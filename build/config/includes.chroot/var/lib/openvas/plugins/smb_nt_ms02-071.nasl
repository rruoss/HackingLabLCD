# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-071.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WM_TIMER Message Handler Privilege Elevation (Q328310)
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
tag_summary = "A security issue has been identified in WM_TIMER that
could allow an attacker to compromise a computer running 
Microsoft Windows and gain complete control over it.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-071.mspx";

if(description)
{
 script_id(11191);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5927);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-1230");
 name = "WM_TIMER Message Handler Privilege Elevation (Q328310)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks Registry for WM_TIMER Privilege Elevation Hotfix (Q328310)";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7) > 0 )
{
 if (hotfix_missing(name:"840987") == 0 ) exit(0);
}
if ( hotfix_check_sp(win2k:4) > 0 )
{
 if (hotfix_missing(name:"840987") == 0 ) exit(0);
 if (hotfix_missing(name:"841533") == 0 ) exit(0);
}


if ( hotfix_missing(name:"328310") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));
