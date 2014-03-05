###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rt_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# RT (Request Tracker) Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to bypass certain
  security restrictions or gain knowledge of sensitive information.
  Impact Level: Application";
tag_affected = "RT (Request Tracker) versions prior to 3.8.9";
tag_insight = "The multiple flaws are caused by,
  - An error when resubmitting form data, which could allow local attackers
    to gain unauthorized access to a user's account.
  - An error when logging SQL queries during a user account transition, which
    could allow attackers to disclose sensitive information.";
tag_solution = "Upgrade to RT (Request Tracker) version 3.8.9 or later,
  For updates refer to http://www.bestpractical.com/rt/";
tag_summary = "This host is installed with Request Tracker and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801857);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1007", "CVE-2011-1008");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("RT (Request Tracker) Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43438");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0475");
  script_xref(name : "URL" , value : "http://lists.bestpractical.com/pipermail/rt-announce/2011-February/000186.html");

  script_description(desc);
  script_summary("Check for the version of Request Tracker");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("rt_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for RT versions prior to 3.8.9
if(vers = get_version_from_kb(port:port,app:"rt_tracker"))
{
  if(version_is_less(version:vers, test_version:"3.8.9")){
    security_warning(port:port);
  }
}
