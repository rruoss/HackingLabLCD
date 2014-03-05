###############################################################################
# OpenVAS Vulnerability Test
# $Id: BlindBlog_1_3_1.nasl 15 2013-10-27 12:49:54Z jan $
#
# BlindBlog Multiple Local File Include and SQL Injection
# Vulnerabilities
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
tag_summary = "BlindBlog is prone to a local file-include vulnerability and
  multiple SQL-injection vulnerabilities because it fails to properly
  sanitize user-supplied input.

  An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute arbitrary local
  files within the context of the webserver process. Information
  harvested may aid in further attacks.

  The attacker can exploit the SQL-injection vulnerabilities to
  compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  BlindBlog 1.3.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100031);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(33980);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("BlindBlog Multiple Local File Include and SQL Injection Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Determine if BlindBlog is vulnerable to SQL Injection and Local File Include");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/blog","/cbblog","/blindblog", cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/comment.php?id=-1%27%20UNION%20ALL%20SELECT%20NULL,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4%20FROM%20cblog_users%23");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if( 
     egrep(pattern: "Author:.*<a href.*>OpenVAS-SQL-Injection-Test</a>", string: buf)
   )
   {    
    security_hole(port:port);
    exit(0);
   }
}
exit(0);
