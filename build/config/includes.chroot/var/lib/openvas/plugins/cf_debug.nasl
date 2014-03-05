# OpenVAS Vulnerability Test
# $Id: cf_debug.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ColdFusion Debug Mode
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
#
# Copyright:
# Copyright (C) 2001 Felix Huber
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
tag_summary = "It is possible to see the ColdFusion Debug Information
by appending ?Mode=debug at the end of the request
(like GET /index.cfm?Mode=debug).

4.5 and 5.0 are definitely concerned (probably in
addition older versions).

The Debug Information usually contain sensitive data such
as Template Path or Server Version.";

tag_solution = "Enter a IP (e.g. 127.0.0.1) in the Debug Settings
			within the ColdFusion Admin.";

# v. 1.06 (last update 07.11.01)

if(description)
{
 script_id(10797);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "ColdFusion Debug Mode";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Get ColdFusion Debug Information";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2001 Felix Huber");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_dependencies("httpver.nasl");
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


dir[0] = "/";
dir[1] = "/index.cfm";
dir[2] = "/index.cfml";
dir[3] = "/home.cfm";
dir[4] = "/home.cfml";
dir[5] = "/default.cfml";
dir[6] = "/default.cfm";


if(get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
        url = string(dir[i], "?Mode=debug");
        req = http_get(item:url, port:port);
        r = http_keepalive_send_recv(port:port, data:req);
	if( r == NULL ) exit(0);
       
	if("CF_TEMPLATE_PATH" >< r)
        	{
        		security_warning(port);
        		exit(0);
        	}
  }
  
 foreach dir (cgi_dirs())
 {
 dirz = string(dir, "/");
 url = string(dirz, "?Mode=debug");
 req = http_get(item:url, port:port);
 r =  http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 if("CF_TEMPLATE_PATH" >< r)
	    {
		    security_warning(port);
		    exit(0);
	    } 
 }
}
