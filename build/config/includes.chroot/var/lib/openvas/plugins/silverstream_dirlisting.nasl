# OpenVAS Vulnerability Test
# $Id: silverstream_dirlisting.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SilverStream directory listing
#
# Authors:
# Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
# modifications by rd:
#	- pattern read is different
#	- request /SilverStream not /SilverStream/Pages
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added links to the Bugtraq message archive
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
tag_summary = "SilverStream directory listings are enabled.
An attacker may use this problem to gain more knowledge
on this server and possibly to get files you would want
to hide.

Reference : http://online.securityfocus.com/archive/101/144786";

tag_solution = "Reconfigure the server so that others
cannot view directory listings";

if(description)
{
 script_id(10846);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "SilverStream directory listing";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks if SilverStream directory listings are disabled.";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Tor Houghton");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
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
     buf = string("/SilverStream");
     buf = http_get(item:buf, port:port);
     rep = http_keepalive_send_recv(port:port, data:buf);
     if ( ! rep ) exit(0);
     lookfor = "<html><head><title>.*SilverStream.*</title>";
      
      if((egrep(pattern:lookfor, string:rep)) && ("/Pages" >< rep))
         security_warning(port);
}

