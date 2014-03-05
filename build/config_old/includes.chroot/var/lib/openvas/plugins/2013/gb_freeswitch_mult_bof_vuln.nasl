###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeswitch_mult_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# FreeSWITCH 'switch_regex.c' Multiple Buffer Overflow Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804025";
CPE = "cpe:/a:freeswitch:freeswitch";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2238");
  script_bugtraq_id(60890);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-07 18:52:44 +0530 (Mon, 07 Oct 2013)");
  script_name("FreeSWITCH 'switch_regex.c' Multiple Buffer Overflow Vulnerabilities");

  tag_summary =
"This host is installed with FreeSWITCH and is prone to multiple buffer overflow
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper validation of user supplied input when handling the
'index[]' variable or when handling 'substituted' variables in switch_regex.c
script.";

  tag_impact =
"Successful exploitation will allow remote attacker to cause multiple buffer
overflows, resulting in a denial of service.

Impact Level: Application";

  tag_affected =
"FreeSWITCH version 1.2";

  tag_solution =
"No solution or patch is available as of 07th October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.freeswitch.org";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/94795");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q3/10");
  script_xref(name : "URL" , value : "http://jira.freeswitch.org/browse/FS-5566");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/07/04/4");
  script_summary("Check for the vulnerable version of FreeSWITCH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freeswitch_detect.nasl");
  script_mandatory_keys("FreeSWITCH/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
switchVer = "";

## Get UDP Port
if(!udp_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get version
if(!switchVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## check the vulnerable versions
if(version_is_equal(version: switchVer, test_version:"1.2.0"))
{
  security_hole(udp_port);
  exit(0);
}
