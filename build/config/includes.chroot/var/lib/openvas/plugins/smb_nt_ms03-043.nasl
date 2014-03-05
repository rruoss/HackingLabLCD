# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-043.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Buffer Overrun in Messenger Service (828035)
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
tag_summary = "A security vulnerability exists in the Messenger Service that could allow 
arbitrary code execution on an affected system. An attacker who successfully 
exploited this vulnerability could be able to run code with Local System 
privileges on an affected system, or could cause the Messenger Service to fail.
Disabling the Messenger Service will prevent the possibility of attack. 

This plugin determined by reading the remote registry that the patch
MS03-043 has not been applied.";

tag_solution = "see http://www.microsoft.com/technet/security/bulletin/ms03-043.mspx";

if(description)
{
 script_id(11888);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8826);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2003-0717");
 script_xref(name:"IAVA", value:"2003-B-0007");
 
 name = "Buffer Overrun in Messenger Service (828035)";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for hotfix Q828035";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB828035") > 0  )
	security_hole(get_kb_item("SMB/transport"));

