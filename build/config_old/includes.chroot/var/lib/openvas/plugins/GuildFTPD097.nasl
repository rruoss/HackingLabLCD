# OpenVAS Vulnerability Test
# $Id: GuildFTPD097.nasl 17 2013-10-27 14:01:43Z jan $
# Description: GuildFTPd Directory Traversal
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
# (slightly modified by rd)
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "Version 0.97 of GuildFTPd was detected. A security vulnerability in
this product allows anyone with a valid FTP login to read arbitrary 
files on the system.";

tag_solution = "Upgrade your FTP server.
More Information : http://www.securiteam.com/windowsntfocus/5CP0S2A4AU.html";

if(description)
{
 script_id(10694);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2789);
 script_cve_id("CVE-2001-0767");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("GuildFTPd Directory Traversal");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Detects the presence of GuildFTPd version 0.97");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# Actual script starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port:port);
if(!banner)exit(0);

if ("GuildFTPD FTP" >< banner) 
{
if ("Version 0.97" >< banner)
 {
  security_warning(port);
 }
}

