###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_invision_power_board_mult_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Invision Power Board Multiple SQL Injection Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_solution = "Apply the following patch,
  http://community.invisionpower.com/topic/291103-invision-power-board-3-0-2-security-update/

  *****
  NOTE: Please ignore this warning if the above mentioned patch is already applied.
  *****";

tag_impact = "Succesful exploitation will allow attackers to access and modify the backend
  database by injecting arbitrary SQL queries.
  Impact Level: Application";
tag_affected = "Invision Power Board version 3.0.0, 3.0.1, and 3.0.2.";
tag_insight = "Tha input passed into 'search_term' parameter in search.php and in 'aid'
  parameter in lostpass.php is not porpperly sanitisied before being used
  to construct SQL queries.";
tag_summary = "The host is running Invision Power Board and is prone to multiple
  SQL Injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900981";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3974");
  script_name("Invision Power Board Multiple SQL Injection Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/387879.php");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2413");

  script_description(desc);
  script_summary("Check for the version of Invision Power Board");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Secpod");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("invision_power_board/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

ipbPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!ipbPort){
  exit(0);
}

if(!ipbVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ipbPort))exit(0);

if(ipbVer =~ "3.0.(0|1|2)"){
  security_hole(ipbPort);
}
