# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-052.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Flaw in Microsoft VM Could Allow Code Execution (810030)
#
# Authors:
# Michael Scheidell SECNAP Network Security
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
tag_summary = "Hotfix to fix Flaw in Microsoft VM
could Allow Code Execution (810030)

Impact of vulnerability: Three vulnerabilities, the most
serious of which could enable an attacker to gain complete
control over a user's system. 

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Versions of the Microsoft virtual machine (Microsoft VM) are
identified by build numbers, which can be determined using the
JVIEW tool as discussed in the FAQ. All builds of the Microsoft
VM up to and including build 5.0.3805 are affected by these
vulnerabilities. 

Supersedes :

http://www.microsoft.com/technet/security/bulletin/ms02-052.mspx

See :
http://www.microsoft.com/technet/security/bulletin/ms02-069.mspx

Also Note: Requires full registry access (Administrator)
to run the test.";

if(description)
{
 script_id(11177);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6371, 6372);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_xref(name:"IAVA", value:"2003-B-0002");
 script_cve_id("CVE-2002-1257","CVE-2002-1258","CVE-2002-1183","CVE-2002-0862");

 name = "Flaw in Microsoft VM Could Allow Code Execution (810030)";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl"); 
 script_require_keys("SMB/registry_full_access", "SMB/WindowsVersion");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("secpod_reg.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);

if ( hotfix_check_sp(xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);

# should be "5,00,3807,0";
v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3809) )
{
 if ( hotfix_missing(name:"810030") > 0 )
   security_hole(port);
}