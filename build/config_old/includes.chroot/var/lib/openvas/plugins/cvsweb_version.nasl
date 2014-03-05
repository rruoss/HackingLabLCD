# OpenVAS Vulnerability Test
# $Id: cvsweb_version.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CVSWeb detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
# - script id
# - more verbose report
# - hole -> warning
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
tag_summary = "CVSWeb is used by hosts to share programming source 
code. Some web sites are misconfigured and allow access
to their sensitive source code without any password protection. 
This plugin tries to detect the presence of a CVSWeb CGI and
when it finds it, it tries to obtain its version.";

tag_solution = "Password protect the CGI if unauthorized access isn't wanted";

if(description)
{
 script_id(10402);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "CVSWeb detection";
 script_name(name);
 
 
desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Checks if CVSWeb is present and gets its version";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
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

foreach dir (cgi_dirs())
{
 req = string(dir, "/cvsweb.cgi/");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if( result == NULL ) exit(0);
 if("CVSweb $Revision:" >< result)
  {
   result = strstr(result, string("CVSweb $Revision: "));
   result = result - strstr(result, string(" $ -->\n"));
   result = result - "CVSweb $Revision: ";
   name = string("www/", port, "/cvsweb/version");
   set_kb_item(name:name, value:result);
   result = string(
"\nThe 'cvsweb' cgi is installed.\n",   
"cvsweb is used to browse the content of a CVS repository\n",
"It can be used by an intruder to obtain the source of your\n",
"programs if you keep them secret.\n\n",
"The installed version of this CGI is : ",  result, "\n\n",
"Solution: Restrict the access to this CGI using password protection,\n",
"or disable it if you do not use it");

   security_warning(port:port, data: result);
   exit(0);
  } 
}
