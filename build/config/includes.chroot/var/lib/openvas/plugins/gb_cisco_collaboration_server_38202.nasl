###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_collaboration_server_38202.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cisco Collaboration Server Source Code Disclosure Vulnerabilities
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
tag_summary = "Cisco Collaboration Server is prone to multiple vulnerabilities that
may allow remote attackers to obtain sourcecode, which may aid them in
further attacks.

Cisco Collaboration Server 5 is vulnerable; other versions may be
affected as well.

NOTE: The vendor has discontinued this product.";


if (description)
{
 script_id(103403);
 script_bugtraq_id(38202);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("Cisco Collaboration Server Source Code Disclosure Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38202");
 script_xref(name : "URL" , value : "http://www.cisco.com/en/US/products/sw/custcosw/ps747/prod_eol_notice09186a008032d4d0.html");

 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-27 13:35:51 +0100 (Fri, 27 Jan 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to obtain sourcecode");
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

url = "/webline/html/admin/wcs/LoginPage.jhtml?oper=login&dest=%2Fadmin%2FCiscoAdmin.jhtml"; 

if(http_vuln_check(port:port, url:url,pattern:"Cisco Administration Log In")) {

  url = "/webline/html/admin/wcs/LoginPage.jhtml%00";

  if(http_vuln_check(port:port, url:url,pattern:"<java>",extra_check:make_list("out.println","AdminDBAuthHelper"))) {

    security_hole(port:port);
    exit(0);

  }  

}

exit(0);
