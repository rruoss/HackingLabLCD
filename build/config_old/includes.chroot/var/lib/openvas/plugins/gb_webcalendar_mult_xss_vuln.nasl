###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcalendar_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WebCalendar Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application";
tag_affected = "WebCalendar versions 1.2.3 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input in various
  scripts, which allows attackers to execute arbitrary HTML and script code on
  the web server.";
tag_solution = "No solution or patch is available as of 6th July, 2011. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://www.k5n.us/webcalendar.php";
tag_summary = "This host is running WebCalendar and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(802305);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WebCalendar Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102785/SSCHADV2011-008.txt");

  script_description(desc);
  script_summary("Check for the version of WebCalendar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webcalendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("webcalendar/installed");
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
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check for WebCalendar versions 1.2.3 and prior.
if(vers = get_version_from_kb(port:port,app:"webcalendar"))
{
  if(version_is_less_equal(version:vers, test_version:"1.2.3")){
    security_warning(port:port);
  }
}
