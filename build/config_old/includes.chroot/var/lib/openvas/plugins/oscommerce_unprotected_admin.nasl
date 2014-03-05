###############################################################################
# OpenVAS Vulnerability Test
# $Id: oscommerce_unprotected_admin.nasl 15 2013-10-27 12:49:54Z jan $
#
# osCommerce unprotected admin directory
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This host is running osCommerce, a widely installed open source shopping e-commerce solution.
  See http://www.oscommerce.com for more information.

  The store admin directory on your server needs to be password protected using .htaccess.
  Most of the time the server you are hosting your store on has the ability to password protect
  directories through the server administration area so check with your host.";

tag_solution = "Limit access to the directory using .htaccess.
  See http://www.oscommerce.info/docs/english/e_post-installation.html for further Information.";

if (description)
{
 script_id(100003);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("osCommerce unprotected admin directory");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if osCommerce admin directory is unprotected");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
 script_require_keys("Software/osCommerce");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = get_kb_list("Software/osCommerce/dir"); 

foreach d (dir)
{ 
 url = string(d, "/admin/customers.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )exit(0);
 if ( ereg(pattern: "^HTTP/1\.[01] +200", string: buf) &&
      egrep(pattern: 'href=.*http.*?gID=.*&selected_box=.*&osCAdminID=', string: buf)
    ) 
   {    
    security_warning(port:port);
    exit(0);
   }
}

exit(0);
