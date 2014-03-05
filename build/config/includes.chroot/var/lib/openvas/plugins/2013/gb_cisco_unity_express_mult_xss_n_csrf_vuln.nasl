###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_unity_express_mult_xss_n_csrf_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cisco Unity Express Multiple XSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  perform certain actions when a logged-in user visits a specially crafted web
  page.
  Impact Level: Application";

tag_affected = "Cisco Unity Express version 7.x";
tag_insight = "- Input passed via the 'gui_pagenotableData' parameter to Web/SA2/ScriptList.do
    and 'holiday.description' parameter to /Web/SA3/AddHoliday.do are not
    properly sanitized before being returned to the user.
  - The application allows users to perform certain actions via HTTP requests
    without performing proper validity checks to verify the requests.";
tag_solution = "Upgrade to Cisco Unity Express 8.0 or later,
  For updated refer to https://sso.cisco.com/autho/forms/CDClogin.html";
tag_summary = "The host is installed with Cisco Unity Express and is prone to
  multiple cross-site scripting and request forgery vulnerabilities.";

if(description)
{
  script_id(803167);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1114", "CVE-2013-1120");
  script_bugtraq_id(57677, 57678);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-06 11:33:49 +0530 (Wed, 06 Feb 2013)");
  script_name("Cisco Unity Express Multiple XSS and CSRF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89837");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89836");
  script_xref(name : "URL" , value : "http://www.osvdb.org/89841");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52045");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24449");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/viewAlert.x?alertId=28044");
  script_xref(name : "URL" , value : "http://infosec42.blogspot.in/2013/02/cisco-unity-express-vulnerabilites.html");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1114");

  script_description(desc);
  script_summary("Check for Cisco Unity Express is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
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


##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Construct the attack request
url = '/Web/SA2/ScriptList.do?gui_pagenotableData=><script>alert' +
      '(document.cookie)</script>';

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(" +
   "document.cookie\)</script>", extra_check:make_list('com.cisco.aesop.vmgui',
   'com.cisco.aesop.gui')))
{
  security_warning(port);
  exit(0);
}
