# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-045.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Buffer Overrun in the ListBox and in the ComboBox (824141)
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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
tag_summary = "A vulnerability exists because the ListBox control and the ComboBox control 
both call a function, which is located in the User32.dll file, that contains 
a buffer overrun. An attacker who had the ability to log on to a system 
interactively could run a program that could send a specially-crafted Windows 
message to any applications that have implemented the ListBox control or the 
ComboBox control, causing the application to take any action an attacker 
specified. An attacker must have valid logon credentials to exploit the 
vulnerability. This vulnerability could not be exploited remotely.";

tag_solution = "see http://www.microsoft.com/technet/security/bulletin/ms03-045.mspx";

if(description)
{
 script_id(11885);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8827);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2003-0659");
 
 name = "Buffer Overrun in the ListBox and in the ComboBox (824141)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for hotfix Q824141";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Jeff Adams");
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

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_check_sp(xp:2, nt:7) > 0 )
{
 if ( hotfix_missing(name:"840987") == 0 ) exit(0);
}

if ( hotfix_check_sp(win2k:5) > 0 )
{
 if ( hotfix_missing(name:"840987") == 0 ) exit(0);
 if ( hotfix_missing(name:"841533") == 0 ) exit(0);
 if ( hotfix_missing(name:"890859") == 0 ) exit(0);
}

if ( hotfix_missing(name:"824141") > 0 )
	security_hole(get_kb_item("SMB/transport"));

