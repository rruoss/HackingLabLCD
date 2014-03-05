###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms04_036.nasl 14 2013-10-27 12:33:37Z jan $
#
# Windows NT NNTP Component Buffer Overflow
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "The Network News Transfer Protocol (NNTP) component of Microsoft
Windows NT Server 4.0, Windows 2000 Server, Windows Server 2003,
Exchange 2000 Server, and Exchange Server 2003 allows remote attackers
to execute arbitrary code via XPAT patterns, possibly related to
improper length validation and an unchecked buffer, leading to
off-by-one and heap-based buffer overflows.";

tag_solution = "Microsoft has released a bulletin that includes fixes to address this
issue for supported versions of the operating system.";

if (description)
{
 script_id(100608);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-26 19:54:51 +0200 (Mon, 26 Apr 2010)");
 script_cve_id("CVE-2004-0574");

 script_name("Windows NT NNTP Component Buffer Overflow");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms04-036.mspx");

script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"risk_factor", value:"Critical");
script_description(desc);
script_summary("Determine if host has critical security update	missing");
script_category(ACT_GATHER_INFO);
script_family("Buffer overflow");
script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
script_dependencies("find_service.nasl", "nntpserver_detect.nasl");
script_require_ports("Services/nntp", 119);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/nntp");
if(!port)port = 119;
if(!get_port_state(port))exit(0);

banner = get_kb_item(string("nntp/banner/", port));
if(!banner || "200 NNTP Service" >!< banner)exit(0);

version = eregmatch(pattern:"^200 NNTP Service .* Version: ([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

VULN = FALSE;

if(version[1] =~ "^5\.5\.") {
  if(version_is_less(version: version[1], test_version:"5.5.1877.79"))  {
   VULN = TRUE; 
  }  
}

else if(version[1] =~ "^5\.0\.") {
  if(version_is_less(version: version[1], test_version:"5.0.2195.6972")) {
    VULN = TRUE;
  }  
} 

else if(version[1] =~ "^6\.0\.") {
  if(version_is_less(version: version[1], test_version:"6.0.3790.206")) {
    VULN = TRUE;
  }  
} 

if(VULN) {
  security_hole(port:port);
  exit(0);
}

exit(0);
