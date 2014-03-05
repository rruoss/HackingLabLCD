###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks.
  Impact Level: Application";
tag_affected = "SolarWinds Orion Network Performance Monitor (NPM) 10.1.2 SP1";
tag_insight = "The flaws are due to an input validation error in NetPerfMon/CustomChart.aspx
  and NetPerfMon/MapView.aspx pages when processing the 'Title' parameter.";
tag_solution = "No solution or patch is available as of 20th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.solarwinds.com/home/";
tag_summary = "This host is running SolarWinds Orion NPM and is prone to cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(801986);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-20 15:38:54 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Sep/107");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105020/orionsolarwinds-xss.txt");
  script_xref(name : "URL" , value : "http://www.derkeiler.com/Mailing-Lists/Full-Disclosure/2011-09/msg00144.html");

  script_description(desc);
  script_summary("Check the version of SolarWinds Orion Network Performance Monitor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orion_npm_detect.nasl");
  script_require_ports("Services/www", 8787);
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
include("version_func.inc");

## Check for the default port
port = get_http_port(default:8787);
if(!get_port_state(port)){
  exit(0);
}

## Check for the asp support
if(!can_host_asp(port:port)){
  exit(0);
}

## Get the version from KB
vers = get_version_from_kb(port:port,app:"orion_npm");
if(vers)
{
  ver = ereg_replace(pattern:" ", replace:".", string:vers);

  ## Check vulnerable version
  if(version_is_equal(version: ver, test_version: "10.1.2.SP1")){
    security_warning(port:port);
  }
}
