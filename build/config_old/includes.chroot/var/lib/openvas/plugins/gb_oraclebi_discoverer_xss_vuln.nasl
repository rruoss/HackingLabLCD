###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oraclebi_discoverer_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OracleBI Discoverer 'node' Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "OracleBI Discoverer Version 10.1.2.48.18";
tag_insight = "The flaw is due to an improper validation of user supplied input to the
  'node' parameter in '/discoverer/app/explorer', which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.";
tag_solution = "No solution or patch is available as of 19th December, 2012. Information
  regarding this issue will updated once the solution details are available.
  http://www.oracle.com/technetwork/developer-tools/discoverer/overview/index.html";
tag_summary = "This host is installed with OracleBI Discoverer and is prone to cross site
  scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803131";
CPE = "cpe:/a:oracle:oraclebi_discoverer";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-19 12:18:56 +0530 (Wed, 19 Dec 2012)");
  script_name("OracleBI Discoverer 'node' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://ur0b0r0x.blogspot.com/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118808/oraclebi-xss.txt");

  script_description(desc);
  script_summary("Check if OracleBI Discoverer is vulnerable to xss");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oraclebi_discoverer_detect.nasl");
  script_require_keys("OracleBIDiscoverer/installed");
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

include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_is_equal(version:vers, test_version:"10.1.2.48.18")){
    security_warning(port);
  }
}
