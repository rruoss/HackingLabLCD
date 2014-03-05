# OpenVAS Vulnerability Test
# $Id: pollit.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Poll It v2.0 cgi
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Changes by rd :
#    - attempt to read /etc/passwd
#    - script_id
#    - script_bugtraq_id(1431);
#
# Copyright:
# Copyright (C) 2000 Thomas Reinke
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
tag_summary = "'Poll_It_SSI_v2.0.cgi' is installed. This CGI has
 a well known security flaw that lets an attacker retrieve any file from
 the remote system, e.g. /etc/passwd.";

tag_solution = "remove 'Poll_It_SSI_v2.0.cgi' from /cgi-bin.";

if(description)
{
 script_id(10459);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1431);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2000-0590");
 name = "Poll It v2.0 cgi";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);

 summary = "Checks for the presence of /cgi-bin/pollit/Poll_It_SSI_v2.0.cgi";
   
 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2000 Thomas Reinke");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
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


if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 req = string(dir, "/pollit/Poll_It_SSI_v2.0.cgi?data_dir=/etc/passwd%00");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_hole(port);
   exit(0);
  }
 }
}
