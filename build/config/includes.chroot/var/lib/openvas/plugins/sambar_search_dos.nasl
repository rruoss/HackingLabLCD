# OpenVAS Vulnerability Test
# $Id: sambar_search_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar Search Results Buffer Overflow Denial of Service
#
# Authors:
# Gareth Phillips - SensePost (www.sensepost.com)
# changes by Tenable:
# - Longer regex to match on
# - Also match on the server version number
#
# Copyright:
# Copyright (C) 2005 SensePost
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
tag_summary = "The remote host is running Sambar Server, a web server package.

The remote version of this software contains a flaw that may allow an attacker 
to crash the service remotely.

A buffer overflow was found in the /search/results.stm application that 
comes shipped with Sambar Server. 

Vulnerable versions: Sambar Server 4.x
		     Sambar Server 5.x
		     Sambar Server 6.0";

tag_solution = "Upgrade to current release of this software";

if(description)
{
 script_id(18650);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id (7975);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Sambar Search Results Buffer Overflow Denial of Service";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 summary = "Sambar Search Results Buffer Overflow DoS";

 script_description(desc);
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2005 SensePost");
 family = "Denial of Service";
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
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);

req = http_get(item:"/search/results.stm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if ( egrep(pattern:"^Server: Sambar (4\.|5\.[01])", string:res, icase:TRUE) )
  security_hole (port);
else if ( egrep(pattern:"&copy; 1997-(199[8-9]|200[0-3]) Sambar Technologies, Inc. All rights reserved.", string:res) ) 
  security_hole (port);

