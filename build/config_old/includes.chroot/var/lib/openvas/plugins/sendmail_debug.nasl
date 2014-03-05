# OpenVAS Vulnerability Test
# $Id: sendmail_debug.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sendmail DEBUG
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 1999 Renaud Deraison
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
tag_solution = "Upgrade your MTA.";

tag_summary = "Your MTA accepts the DEBUG mode.

This mode is dangerous as it allows remote
users to execute arbitrary commands as root
without the need to log in.";

if(description)
{
 script_id(10247);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(1);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-1999-0095");
 
 name = "Sendmail DEBUG";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
		    
 
 summary = "Checks for the presence of the DEBUG mode"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 Renaud Deraison");
 
 family = "SMTP problems";
 script_family(family);
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_exclude_keys("SMTP/wrapped");

 script_require_ports("Services/smtp", 25);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);
if(get_kb_item("SMTP/wrapped"))exit(0);

soc = open_sock_tcp(port);
if(soc)
 {
  b = smtp_recv_banner(socket:soc);

  s = string("debug\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  r = tolower(r);

  
  if(("200 debug set" >< r))security_hole(port);
  close(soc);
}
