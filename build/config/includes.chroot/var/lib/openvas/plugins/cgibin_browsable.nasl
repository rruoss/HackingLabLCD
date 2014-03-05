# OpenVAS Vulnerability Test
# $Id: cgibin_browsable.nasl 17 2013-10-27 14:01:43Z jan $
# Description: /cgi-bin directory browsable ?
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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
tag_summary = "The /cgi-bin directory is browsable.
This will show you the name of the installed common scripts 
and those which are written by the webmaster and thus may be 
exploitable.";

tag_solution = "Make the /cgi-bin non-browsable.";

if(description)
{
 script_id(10039);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "/cgi-bin directory browsable ?";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Is /cgi-bin browsable ?";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");

 family = "Web application abuses";
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
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = NULL;
report_head = "
The following CGI directories are browsable :
";

report_tail = "


This shows an attacker the name of the installed common scripts and those 
which are written by the webmaster and thus may be exploitable.

Solution: Make these directories non-browsable. ";

foreach dir (cgi_dirs())
{
 if ( strlen(dir) )
 {
 data = string(dir ,"/");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))
 {
  buf = tolower(buf);
  if(dir == "") must_see = "index of";
  else must_see = string("<title>", dir);
  if( must_see >< buf ){
  	dirs += '.  ' + dir + '\n';
	}
 }
 }
}

if (dirs != NULL )
{
 security_warning(port:port, data:report_head + dirs + report_tail);
}


