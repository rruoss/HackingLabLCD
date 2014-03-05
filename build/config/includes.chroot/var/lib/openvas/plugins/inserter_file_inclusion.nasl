# OpenVAS Vulnerability Test
# $Id: inserter_file_inclusion.nasl 17 2013-10-27 14:01:43Z jan $
# Description: inserter.cgi File Inclusion and Command Execution Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "The remote web server contains the 'inserter' CGI.

The inserter.cgi contains a vulnerability that allows remote attackers to cause
the CGI to execute arbitrary commands with the privileges of the web server 
by supplying it with a piped instruction or to include arbitrary files by 
providing an absolute path to the location of the file.";

tag_solution = "Delete this file";

# From: fireboy fireboy <fireboynet@webmails.com>
# remote command execution in inserter.cgi script
# 2005-04-25 07:19

if(description)
{
 script_id(18149);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "inserter.cgi File Inclusion and Command Execution Vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of a file inclusion vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
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

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get (item: string(loc, "/inserter.cgi?/etc/passwd"), port: port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list(cgi_dirs()))
{
 check(loc:dir);
}

