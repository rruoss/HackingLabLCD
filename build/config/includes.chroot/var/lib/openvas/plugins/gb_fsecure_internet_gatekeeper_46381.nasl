###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_internet_gatekeeper_46381.nasl 13 2013-10-27 12:16:33Z jan $
#
# F-Secure Internet Gatekeeper Log File Information Disclosure Vulnerability
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
tag_summary = "F-Secure Internet Gatekeeper is prone to an information-disclosure
vulnerability.

Attackers can exploit this issue to gain access to sensitive
information. Information obtained may lead to other attacks.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103082);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)");
 script_bugtraq_id(46381);
 script_cve_id("CVE-2011-0453");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("F-Secure Internet Gatekeeper Log File Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46381");
 script_xref(name : "URL" , value : "https://europe.f-secure.com/products/fsigkl/");
 script_xref(name : "URL" , value : "http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-1.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed F-Secure Internet Gatekeeper is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 9012);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:9012);
if(!get_port_state(port))exit(0);

if(!dir =  get_dir_from_kb(port:port,app:"f_secure_internet_gatekeeper"))exit(0);
url = string(dir, "/fsecure/log/fssp.log"); 

if(http_vuln_check(port:port, url:url,pattern:"F-Secure Security Platform",extra_check:make_list("Database version:","Starting ArchiveScanner engine"))) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);

