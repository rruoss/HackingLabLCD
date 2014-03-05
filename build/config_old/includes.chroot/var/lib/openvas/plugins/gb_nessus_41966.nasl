###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nessus_41966.nasl 14 2013-10-27 12:33:37Z jan $
#
# Nessus Web Server Plugin Unspecified Cross Site Scripting Vulnerability
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
tag_summary = "Nessus Web Server is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Versions prior to Nessus Web Server 1.2.4 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100728);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(41966);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2010-2914", "CVE-2010-2989");

 script_name("Nessus Web Server Plugin Unspecified Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41966");
 script_xref(name : "URL" , value : "https://discussions.nessus.org/message/7245");
 script_xref(name : "URL" , value : "http://www.nessus.org");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512645");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Nessus Web Server is prone to a cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8834);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("openvas-https.inc");
include("version_func.inc");

port = get_http_port(default:8834);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(isnull(banner) || "NessusWWW" >!< banner)exit(0);

req = string("GET /feed HTTP/1.1\r\nHost: ",get_host_name(),"\r\n");
buf = https_req_get(port:port,request:req);

version = eregmatch(pattern:"<web_server_version>([0-9.]+)</web_server_version>", string:buf);
if(isnull(version[1]) || version[1] == "0.0.0")exit(0);

if(version_is_less(version:version[1],test_version:"1.2.4")) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
