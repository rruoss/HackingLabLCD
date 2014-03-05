###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_cmd_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# HP System Management Homepage Command Injection Vulnerability-July2013
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803846";
CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3576");
  script_bugtraq_id(60471);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-30 13:30:42 +0530 (Tue, 30 Jul 2013)");
  script_name("HP System Management Homepage Command Injection Vulnerability-July2013");

  tag_summary =
"This host is running HP System Management Homepage (SMH) and is prone to
command injection  vulnerability.";

  tag_vuldetect =
"Get the installed version of HP SMH with the help of detect NVT and check
it is vulnerable or not.";

  tag_insight =
"The flaw is triggered when the ginkgosnmp.inc script uses the last path
segment of the current requested URL path in an exec call without properly
sanitizing the content.";

  tag_impact =
"Successful exploitation will allow an authenticated remote attacker to execute
arbitrary commands.";

  tag_affected =
"HP System Management Homepage (SMH) version 7.2.1.3 and prior";

  tag_solution =
"No solution or patch is available as of 30th July, 2013. Information
regarding this issue will be updated once the solution details are available.
http://h18013.www1.hp.com/products/servers/management/agents/index.html";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/94191");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26420");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/735364");
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2381);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
version = NULL;

## Get HP SMH Port
if(! port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)) exit(0);

## Get HP SMH Version
if(! version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) exit(0);

## Check for HP System Management Homepage versions
if(version_is_less_equal(version:version, test_version:"7.2.1.3"))
{
  security_hole(port);
  exit(0);
}
