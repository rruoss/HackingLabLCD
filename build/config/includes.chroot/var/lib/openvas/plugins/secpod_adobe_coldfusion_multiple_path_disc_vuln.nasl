###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_coldfusion_multiple_path_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe ColdFusion Multiple Path Disclosure Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Adobe ColdFusion version 9 and prior.";
tag_insight = "The flaw is due to insufficient error checking, allows remote
  attackers to obtain sensitive information via a direct request to a
  .cfm file, which reveals the installation path in an error message.";
tag_solution = "No solution or patch is available as of 17th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/products/coldfusion-family.html";
tag_summary = "The host is running Adobe ColdFusion and is prone to multiple path
  disclosure vulnerabilities.";

if(description)
{
  script_id(902586);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-17 10:10:10 +0530 (Thu, 17 Nov 2011)");
  script_name("Adobe ColdFusion Multiple Path Disclosure Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5377/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Nov/250");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107017/adobecoldfusion-disclosedos.txt");

  script_description(desc);
  script_summary("Determine if Adobe ColdFusion is vulnerable to Path Disclosure");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm ColdFusion
if(!get_kb_item(string("coldfusion/", port, "/installed"))){
  exit(0);
}

## Try Attack and check the response to confirm vulnerability
if(http_vuln_check(port:port,
   url:"/CFIDE/adminapi/_datasource/formatjdbcurl.cfm",
   pattern:".*\\wwwroot\\CFIDE\\adminapi\\_datasource\\formatjdbcurl.cfm",
   extra_check:"Unable to display error's location in a CFML template.")) {
  security_warning(port);
}
