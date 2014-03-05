# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-051.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Microsoft RDP flaws could allow sniffing and DOS(Q324380)
#
# Authors:
# Michael Scheidell SECNAP Network Security
# Updated: 2009/04/23
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
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
tag_summary = "Remote Data Protocol (RDP) version 5.0 in Microsoft
Windows 2000 and RDP 5.1 in Windows XP does not
encrypt the checksums of plaintext session data,
which could allow a remote attacker to determine the
contents of encrypted sessions via sniffing, and 
Remote Data Protocol (RDP) version 5.1 in Windows
XP allows remote attackers to cause a denial of
service (crash) when Remote Desktop is enabled via a
PDU Confirm Active data packet that does not set the
Pattern BLT command.

Impact of vulnerability: Two vulnerabilities:
information disclosure, denial of service.

Maximum Severity Rating: Moderate. 

Recommendation: Administrators of Windows
2000 terminal servers and Windows XP users
who have enabled Remote Desktop should apply
the patch.

Affected Software: 

Microsoft Windows 2000 
Microsoft Windows XP";

tag_solution = "http://www.microsoft.com/technet/security/bulletin/ms02-051.mspx";

if(description)
{
 script_id(11146);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5410, 5711, 5712);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-0863", "CVE-2002-0864");

 name = "Microsoft RDP flaws could allow sniffing and DOS(Q324380)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for MS Hotfix Q324380, Flaws in Microsoft RDP";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
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

if ( hotfix_check_sp(xp:1, win2k:4) <= 0 ) exit(0);
if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_missing(name:"Q324380") > 0 )
	security_warning(get_kb_item("SMB/transport"));

