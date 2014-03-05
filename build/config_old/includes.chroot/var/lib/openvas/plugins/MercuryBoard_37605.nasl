###############################################################################
# OpenVAS Vulnerability Test
# $Id: MercuryBoard_37605.nasl 14 2013-10-27 12:33:37Z jan $
#
# MercuryBoard 'index.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "MercuryBoard is prone to a cross-site scripting vulnerability because
the application fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may help the attacker steal cookie-based authentication
credentials and launch other attacks.

MercuryBoard 1.1.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100424);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)");
 script_bugtraq_id(37605);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("MercuryBoard 'index.php' Cross-Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if MercuryBoard is prone to a cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("MercuryBoard_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37605");
 script_xref(name : "URL" , value : "http://www.mercuryboard.com/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/mercuryboard")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir = matches[2];

url = string(dir,"/index.php/%3E%22%3E%3CScRiPt%3Ealert(%27openvas-xss-test%27)%3C/ScRiPt%3E"); 
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);  
if( buf == NULL )continue;

if(egrep(pattern: "<ScRiPt>alert\('openvas-xss-test'\)</ScRiPt>", string: buf, icase: TRUE)) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
