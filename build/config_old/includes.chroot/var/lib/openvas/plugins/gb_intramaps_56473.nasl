###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intramaps_56473.nasl 12 2013-10-27 11:15:33Z jan $
#
# Intramaps Multiple Security Vulnerabilities
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
tag_summary = "Intramaps is prone to multiple security vulnerabilities including:

1. Multiple cross-site scripting vulnerabilities
2. Multiple SQL-injection vulnerabilities
3. An information-disclosure vulnerability
4. A cross-site request-forgery vulnerability
5. An XQuery-injection vulnerability

An attacker can exploit these vulnerabilities to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
access or modify data, exploit vulnerabilities in the underlying
database, disclose sensitive information, and perform unauthorized
actions. Other attacks are also possible.

Intramaps 7.0.128 Rev 318 is vulnerable; other versions may also
be affected.";

tag_solution = "Reportedly these issues are fixed. Please contact the vendor for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103605";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56473);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("Intramaps Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56473");
 script_xref(name : "URL" , value : "http://www.stratsec.net/Research/Advisories/Intramaps-Multiple-Vulnerabilities-%28SS-2012-007%29");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-12 10:40:31 +0100 (Mon, 12 Nov 2012)");
 script_description(desc);
 script_summary("Determine if Intramaps is prone to xss");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/IntraMaps","/intramaps75","/IntraMaps70",cgi_dirs());
subdirs = make_list("/applicationengine","/ApplicationEngine/");

foreach dir (dirs) {
  foreach subdir (subdirs) {
   
    url = dir + subdir + '/'; 

    if(http_vuln_check(port:port, url:url,pattern:"<title>IntraMaps")) {
    
      url = dir + subdir + "/Application.aspx?project=NAME</script><script>alert('openvas-xss-test')</script>";

      if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE)) {
        security_hole(port:port);
        exit(0);
      }  
    }
  }
}

exit(0);

