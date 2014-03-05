# OpenVAS Vulnerability Test
# $Id: ssh_bruteforce.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SSH1 SSH Daemon Logging Failure
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
tag_summary = "You are running SSH Communications Security SSH 1.2.30, or previous.

This version does not log repeated login attempts, which 
could allow remote attackers to compromise accounts 
without detection via a brute force attack.";

tag_solution = "Patch and New version are available from SSH.";

if(description)
{
 script_id(11341);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2345);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0471");
 
 name = "SSH1 SSH Daemon Logging Failure";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;	
 script_description(desc);
 
 summary = "Checks for the remote SSH version";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

if ( "openssh" >< tolower(banner) ) exit(0);


#Looking for SSH product version number from 1.0 to 1.2.30
if(ereg(string:banner,
  	pattern:"^SSH-.*-1\.([0-1]|[0-1]\..*|2\.([0-9]|1[0-9]|2[0-9]|30))[^0-9]*$", icase:TRUE))security_hole(port);



