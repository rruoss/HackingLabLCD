###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_manageengine_servicedesk_plus_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ManageEngine ServiceDesk Plus Multiple Stored XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks.
  Impact Level: Application";
tag_affected = "ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.";
tag_insight = "Multiple flaws are due to an error in,
  -'WorkOrder.do', 'Problems.cc', 'AddNewProblem.cc', 'ChangeDetails.c' when
    processing the 'reqName' parameter.
  - 'WorkOrder.do' when processing the verious parameters.
  - 'AddSolution.do' when handling add action via ' keywords' and 'comment'
    parameters.
  - 'ContractDef.do' when processing the 'supportDetails', 'contractName'
    and 'comments' parameters.
  - 'VendorDef.do' and 'MarkUnavailability.jsp' hen processing the
    'organizationName' and 'COMMENTS' parameters.
  - 'HomePage.do', 'MySchedule.do', and 'WorkOrder.d' when handling the HTTP
     header elements 'referer' and 'accept-language'.";
tag_solution = "Upgrade to ManageEngine ServiceDesk Plus 8.0 Build 8015 or later
  For updates refer to http://www.manageengine.com/";
tag_summary = "This host is running ManageEngine ServiceDesk Plus and is prone to
  multiple stored cross site scripting vulnerabilities.";

if(description)
{
  script_id(902469);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("ManageEngine ServiceDesk Plus Multiple Stored XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.manageengine.com/products/service-desk/readme-8.0.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104365/ZSL-2011-5039.txt");

  script_description(desc);
  script_summary("Check the version of ManageEngine ServiceDesk Plus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_require_ports("Services/www", 8080);
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

## Get HTTP Port
port = get_http_port(default:8080);
if(!get_port_state(port)) {
  exit(0);
}

## Get ManageEngine ServiceDesk Plus Installed version
if(!vers = get_version_from_kb(port:port,app:"ManageEngine")){
  exit(0);
}

## Check the build version
if(' Build ' >< vers){
  vers = ereg_replace(pattern:" Build ", string:vers, replace:".");
}

if(version_is_less_equal(version:vers, test_version:"8.0.0.8014")){
  security_warning(port:port);
}
