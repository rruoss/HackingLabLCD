###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_http_server_xss_header_injection_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Oracle HTTP Server for Oracle Application Server 10g Release 2.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'Expect' header from an HTTP request, which allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "Upgrade to Oracle HTTP Server 11g or later,
  For updates refer to http://www.oracle.com/technetwork/middleware/ias/downloads/index.html";
tag_summary = "This host is running Oracle HTTP Server and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(902526);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17393/");
  script_xref(name : "URL" , value : "http://www.securiteam.com/securityreviews/5KP0M1FJ5E.html");
  script_xref(name : "URL" , value : "http://www.yaboukir.com/wp-content/bugtraq/XSS_Header_Injection_in_OHS_by_Yasser.pdf");

  script_description(desc);
  script_summary("Check if Oracle HTTP Server is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application
banner = get_http_banner(port: port);
if("Server: Oracle-Application-Server" >!< banner ||
   "Oracle-HTTP-Server" >!< banner) {
  exit(0);
}

## Construct attack request
req = string("GET /index.html HTTP/1.1\r\n",
             "Host: ",get_host_name(),"\r\n",
             "Expect: <script>alert('openvas-xss-test')</script>\r\n\r\n");

## Try XSS Attack
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Check the response to confirm vulnerability
if("Expect: <script>alert('openvas-xss-test')</script>" >< res){
  security_warning(port);
}
