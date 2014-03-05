# OpenVAS Vulnerability Test
# $Id: osCommerce_dirtraversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: osCommerce directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host is running osCommerce, a widely installed open source 
shopping e-commerce solution.

The remote version of this software is vulnerable to a directory traversal 
flaw which may be exploited by an attacker to read arbitrary files
on the remote server with the privileges of the web server.";

tag_solution = "Upgrade to a newer version of this software";

# Ref:  Rene <l0om@excluded.org> and Megasky <magasky@hotmail.com>

if (description)
{
 script_id(17595);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2021");
 script_bugtraq_id(10364);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("osCommerce directory traversal");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("Determine if osCommerce is vulnerable to dir traversal");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
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

if (!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

dir = get_kb_list("Software/osCommerce/dir");

foreach d (dir)
{
 url = string(d, "/admin/file_manager.php?action=read&filename=../../../../../../../../etc/passwd");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if (egrep(pattern:"root:0:[01]:.*", string:buf))
 {
   security_warning(port:port);
   exit(0);
 }
}
