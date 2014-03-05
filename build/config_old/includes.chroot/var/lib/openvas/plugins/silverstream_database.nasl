# OpenVAS Vulnerability Test
# $Id: silverstream_database.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SilverStream database structure
#
# Authors:
# Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
# Changes by rd:
# - phrasing in the report
# - pattern read
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2002 Tor Houghton
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
tag_summary = "It is possible to download the remote SilverStream database
structure by requesting :
	http://www.example.com/SilverStream/Meta/Tables/?access-mode=text
	
	
An attacker may use this flaw to gain more knowledge about
this host.

Reference : http://online.securityfocus.com/archive/101/144786";

tag_solution = "Reconfigure the server so that others
cannot view database structure";

if(description)
{
 script_id(10847);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "SilverStream database structure";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks if SilverStream database structure is visible.";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Tor Houghton");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port)) {
      buf = string("/SilverStream/Meta/Tables/?access-mode=text");
      buf = http_get(item:buf, port:port);
      rep = http_keepalive_send_recv(port:port, data:buf);
      if("_DBProduct" >< rep)
         security_warning(port);
}

