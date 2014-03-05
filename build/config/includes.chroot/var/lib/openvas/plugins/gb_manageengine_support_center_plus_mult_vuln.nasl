###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_support_center_plus_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine Support Center Plus Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to upload malicious code
  (backdoors/shells) or insert arbitrary HTML and script code, which will be
  executed in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "ManageEngine Support Center Plus 7.9 Upgrade Pack 7908 and prior";
tag_insight = "Multiple flaws are due to,
  - An improper checking of image extension when uploading the files. This will
    lead to uploading web site files which could be used for malicious actions.
  - An input passed to the 'fromCustomer' parameter via 'HomePage.do' script is
    not properly sanitised before being returned to the user.
  - An input passed to multiple parameters via 'WorkOrder.do' script is not
    properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 18th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.com/products/support-center/";
tag_summary = "This host is running Zoho ManageEngine Support Center Plus and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(802477);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-18 10:24:32 +0530 (Thu, 18 Oct 2012)");
  script_name("Zoho ManageEngine Support Center Plus Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22040/");
  script_xref(name : "URL" , value : "http://www.bugsearch.net/en/13746/manageengine-support-center-plus-7908-multiple-vulnerabilities.html");

  script_description(desc);
  script_summary("Check if Zoho ManageEngine Support Center Plus is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

## Variable Initialization
port = 0;

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm the application
if(http_vuln_check(port:port, url:"/", pattern:">ManageEngine SupportCenter Plus<",
                   check_header:TRUE, extra_check:'ZOHO Corp'))
{
  ## Construct the attack request
  url = '/HomePage.do?fromCustomer=%27;alert(document.cookie);' +
        '%20var%20frompor=%27null';

  ## confirm the exploit
  if(http_vuln_check(port:port, url:url,
                   pattern:"';alert\(document.cookie\); var frompor='null",
                   check_header:TRUE,
                   extra_check:'>ManageEngine SupportCenter Plus</'))
  {
    security_hole(port:port);
    exit(0);
  }
}
