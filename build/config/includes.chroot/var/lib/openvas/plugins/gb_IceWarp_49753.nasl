###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_IceWarp_49753.nasl 13 2013-10-27 12:16:33Z jan $
#
# IceWarp Web Mail Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "IceWarp Web Mail is prone to multiple information-disclosure
vulnerabilities.

Attackers can exploit these issues to gain access to potentially
sensitive information, and possibly cause denial-of-service
conditions; other attacks may also be possible.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(103279);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)");
 script_bugtraq_id(49753);
 script_cve_id("CVE-2011-3579","CVE-2011-3580");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

 script_name("IceWarp Web Mail Multiple Information Disclosure Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49753");
 script_xref(name : "URL" , value : "http://www.icewarp.com/Products/IceWarp_Web_Mail/");
 script_xref(name : "URL" , value : "https://www.trustwave.com/spiderlabs/advisories/TWSL2011-013.txt");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed IceWarp is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
if(!can_host_php(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "IceWarp" >!< banner)exit(0);

dirs = make_list("/webmail",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/server/"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title>phpinfo\(\)")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

