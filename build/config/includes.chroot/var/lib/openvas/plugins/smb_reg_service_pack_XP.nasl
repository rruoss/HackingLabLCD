# OpenVAS Vulnerability Test
# $Id: smb_reg_service_pack_XP.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SMB Registry : XP Service Pack version
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# Copyright:
# Copyright (C) 2002 Alert4Web.com
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
tag_summary = "Remote system has latest service pack installed.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine the Service Pack version of the Windows XP
system.";

tag_solution = "Apply Windows XP Service Pack 2.";

 desc = "
 Summary:
 " + tag_summary;

 desc_hole = "
Summary:

Remote system is not up to date.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows XP system is not
up to date.

 Solution:
 " + tag_solution;

if(description)
{
 script_id(11119);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10897, 11202);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-1999-0662");
 
 name = "SMB Registry : XP Service Pack version";
 
 script_name(name);
 
 desc = "
This script reads the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service pack for security reasons.";

 script_description(desc);
 
 summary = "Determines the remote SP";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Alert4Web.com");
 family = "Windows";
 script_family(family);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

if ( get_kb_item("SMB/RegOverSSH") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.1")
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);
 else
 {
  report = string (desc_hole,
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has no service pack applied.\n");

  security_warning(data:report, port:port);
  exit(0);
 }

 if (sp == "Service Pack 2")
 {
  report = string (desc,
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has ", sp , " applied.\n");

  security_note(data:report, port:port);
  exit(0);
 }
 
 if(sp == "Service Pack 1")
 {
  report = string (desc_hole,
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has ", sp, " applied.\n",		
		"Apply SP2 to be up-to-date.\n");

  security_warning(data:report, port:port);
  exit(0);
 }
}
