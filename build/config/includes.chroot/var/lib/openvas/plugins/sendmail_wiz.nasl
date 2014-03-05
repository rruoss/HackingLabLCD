# OpenVAS Vulnerability Test
# $Id: sendmail_wiz.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sendmail WIZ
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "Your MTA accepts the WIZ command. It must be a very old version
of sendmail.
WIZ allows remote users to execute arbitrary commands as root
without the need to log in.";

tag_solution = "reconfigure it or upgrade your MTA.";

if(description)
{
 script_id(16024);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2897);
 script_cve_id("CVE-1999-0145");
 script_xref(name:"OSVDB", value:"1877");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Sendmail WIZ";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
		    
 
 summary = "Checks for sendmail WIZ command"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 
 family = "SMTP problems";
 script_family(family);
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_exclude_keys("SMTP/wrapped");

 script_require_ports("Services/smtp", 25);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(! port) port = 25;
if(! get_port_state(port)) exit(0);
# if (get_kb_item("SMTP/wrapped")) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);
b = smtp_recv_banner(socket:soc);
if ( ! b || "Sendmail" >!< b ) exit(0);
s = string("WIZ\r\n");
# We could also test the "KILL" function, which is related to WIZ if I
# understood correctly
send(socket:soc, data:s);
r = recv_line(socket:soc, length:1024);
if(ereg(string: r, pattern: "^2[0-9][0-9]")) security_hole(port);
close(soc);

