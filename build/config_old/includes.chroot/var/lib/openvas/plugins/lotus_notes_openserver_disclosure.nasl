# OpenVAS Vulnerability Test
# $Id: lotus_notes_openserver_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus Notes ?OpenServer Information Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Solution by David Litchfield (david@nextgenss.com)
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2001 by Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "A default behavior of Lotus Notes allows remote users to enumerate existing databases on a remote Domino (Lotus Notes) server. This information is considered sensitive, since it might reveal versions, logs, statistics, etc.";

tag_solution = "To disable this behavior open names.nsf and edit the Servers document in the Server view. From the Internet Protocols tab set 'Allow HTTP Clients to browse databases' to No.
This command doesn't affect a single database - it is a server-wide issue.

Additional information:
http://www.securiteam.com/securitynews/6W0030U35W.html
http://online.securityfocus.com/archive/1/223810";


if(description)
{
 script_id(10795); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Lotus Notes ?OpenServer Information Disclosure";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Lotus Notes ?OpenServer Information Disclosure";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web Servers";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
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

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

req = http_get(item:"/?OpenServer", port:port);
soc = http_open_socket(port);
if (soc)
{
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);
 #display(buf);
    
 if ((egrep(pattern:"!-- Lotus-Domino", string:buf)) && (egrep(pattern:"/icons/abook.gif", string:buf)))
 {
  security_warning(port:port);
  exit(0);
 }
}
