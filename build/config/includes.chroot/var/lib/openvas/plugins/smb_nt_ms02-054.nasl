# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-054.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Unchecked Buffer in Decompression Functions(Q329048)
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
tag_summary = "Two vulnerabilities exist in the Compressed Folders function: 

An unchecked buffer exists in the programs that handles
the decompressing of files from a zipped file. A
security vulnerability results because attempts to open
a file with a specially malformed filename contained in
a zipped file could possibly result in Windows Explorer
failing, or in code of the attacker's choice being run.

The decompression function could place a file in a
directory that was not the same as, or a child of, the
target directory specified by the user as where the
decompressed zip files should be placed. This could
allow an attacker to put a file in a known location on
the users system, such as placing a program in a
startup directory

Impact of vulnerability: Two vulnerabilities, the most serious
of which could run code of attacker's choice

Maximum Severity Rating: Moderate 

Recommendation: Consider applying the patch to affected systems 

Affected Software: 

Microsoft Windows 98 with Plus! Pack 
Microsoft Windows Me 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-054.mspx";

if(description)
{
 script_id(11148);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5873, 5876);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0370", "CVE-2002-1139"); 

 name = "Unchecked Buffer in Decompression Functions(Q329048)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for MS Hotfix Q329048, Unchecked Buffer in Decompression functions";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
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


if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"329048") > 0 &&
     hotfix_missing(name:"873376") > 0 )
	security_hole(get_kb_item("SMB/transport"));

