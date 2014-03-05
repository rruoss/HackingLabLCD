##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Collabtive 'managechat.php' SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to bypass security
  restrictions and gain unauthorized administrative access to the vulnerable
  application.
  Impact Level: Application.";
tag_affected = "Collabtive version 0.6.5";

tag_insight = "The flaws are due to an improper validation of authentication cookies
  in the 'managechat.php' script when processing the value of parameter 'actions'.";
tag_solution = "No solution or patch is available as of 24th November, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.collabtive.com";
tag_summary = "This host is running Collabtive and is prone SQL injection
  vulnerability.";

if(description)
{
  script_id(801548);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-4269");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Collabtive 'managechat.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62930");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15381/");

  script_description(desc);
  script_summary("Check Collabtive vulnerable version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_collabtive_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

if(!version = get_version_from_kb(port:port, app:"collabtive")){
  exit(0);
}

## Check the AV Arcade version
if(version_is_equal(version:version, test_version:"0.6.5")){
  security_hole(port);
}
