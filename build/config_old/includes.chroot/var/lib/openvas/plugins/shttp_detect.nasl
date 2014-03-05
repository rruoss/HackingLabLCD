# OpenVAS Vulnerability Test
# $Id: shttp_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: S-HTTP detection
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
tag_summary = "This web server supports S-HTTP, a cryptographic layer 
that was defined in 1999 by RFC 2660. 
S-HTTP has never been widely implemented and you should 
use HTTPS instead.

As rare or obsolete code is often badly tested, it would be 
safer to use another server or disable this layer somehow.";

# Refereces:
# RFC 2660 The Secure HyperText Transfer Protocol

if(description)
{
 script_id(11720);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
  name = "S-HTTP detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Checks if the web server accepts the Secure method";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("http_func.inc");
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);
req = string("Secure * Secure-HTTP/1.4\r\n",
		"Host: ", get_host_name(), ":", port, "\r\n",
		"Connection: close\r\n",
		"\r\n");
send(socket: soc, data: req);
r = recv_line(socket: soc, length: 256);
http_close_socket(soc);
if (ereg(pattern:"Secure-HTTP/[0-9]\.[0-9] 200 ", string:r)) security_warning(port);
