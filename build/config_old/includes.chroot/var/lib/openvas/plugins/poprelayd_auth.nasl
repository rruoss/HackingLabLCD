# OpenVAS Vulnerability Test
# $Id: poprelayd_auth.nasl 17 2013-10-27 14:01:43Z jan $
# Description: poprelayd & sendmail authentication problem
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "The remote SMTP server allows relaying for authenticated users. 
It is however possible to poison the logs; this means that spammers
would be able to use your server to send their e-mails to
the world, thus wasting your network bandwidth and getting you
blacklisted.

*** Some SMTP servers such as Postfix will display a false positive
*** here";

tag_solution = "Disable poprelayd";

# References:
# Date:  Tue, 3 Jul 2001 19:05:10 +0200 (CEST)
# From: "Andrea Barisani" <lcars@infis.univ.trieste.it>
# To: bugtraq@securityfocus.com
# Subject: poprelayd and sendmail relay authentication problem (Cobalt Raq3)

if(description)
{
 script_id(11080);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2986);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-1075");
 name = "poprelayd & sendmail authentication problem";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
		    
 
 summary = "Checks if the remote mail server can be used as a spam relay"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 
 family = "SMTP problems";
 script_family(family);
 script_dependencies("smtpserver_detect.nasl", "sendmail_expn.nasl", 
		"smtp_relay.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/postfix", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("smtp_func.inc");

# can't perform this test on localhost
if(islocalhost())exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
if(!data)exit(0);

domain = get_kb_item("Settings/third_party_domain");
 
hel = string("HELO ", domain, "\r\n");
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
mf1 = string("MAIL FROM: <test_1@", domain, ">\r\n");
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
rc1 = string("RCPT TO: <test_2@", domain, ">\r\n");
send(socket:soc, data: rc1);
data = recv_line(socket:soc, length:1024);
if ("Relaying denied. Please check your mail first." >< data) { suspicious=1;}
else if(ereg(pattern:"^250 .*", string:data))exit(0);

q = raw_string(0x22);	# Double quote
h = this_host();
mf = string("mail from:", q, "POP login by user ", q, "admin", q,
	" at (", h, ") ", h, "@example.org\r\n");
send(socket: soc, data: mf);
data = recv_line(socket:soc, length:1024);
close(soc);
#
#sleep(10);
#
soc = open_sock_tcp(port);
if (!soc) exit(0);

data = smtp_recv_banner(socket:soc);
send(socket:soc, data:hel);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data:mf1);
data = recv_line(socket:soc, length:1024);
send(socket:soc, data: rc1);
i = recv_line(socket:soc, length:4);
if (i == "250 ") security_warning(port);
close(soc);
