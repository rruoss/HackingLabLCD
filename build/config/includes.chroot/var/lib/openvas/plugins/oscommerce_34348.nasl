###############################################################################
# OpenVAS Vulnerability Test
# $Id: oscommerce_34348.nasl 15 2013-10-27 12:49:54Z jan $
#
# osCommerce 'oscid' Session Fixation Vulnerability
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
tag_summary = "osCommerce is prone to a session-fixation vulnerability.

  Attackers can exploit this issue to hijack a user's session and gain
  unauthorized access to the affected application.

  The following are vulnerable:

  osCommerce 2.2
  osCommerce 3.0 Beta

  Other versions may also be affected.";


if (description)
{
 script_id(100099);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)");
 script_bugtraq_id(34348);
 script_tag(name:"cvss_base", value:"8.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("osCommerce 'oscid' Session Fixation Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if osCommerce is vulnerable to Session Fixation");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
 script_require_keys("Software/osCommerce");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34348");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/oscommerce")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir  = matches[2];

if(!isnull(dir))
{ 
 url = string(dir, "/index.php?osCsid=a815a815a815a815");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )exit(0);
 if(egrep(pattern:"[a-zA-Z]+\.php\?osCsid=a815a815a815a815", string: buf) && !egrep(pattern:"Set-Cookie: osCsid=[a-zA-Z0-9]+" , string: buf) )
   {    
    security_hole(port:port);
    exit(0);
   }
}

exit(0);
