###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_mult_int_overflow_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# PuTTY Multiple Integer Overflow Vulnerabilities (Windows)
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
  Impact Level: System/Application";

CPE = "cpe:/a:putty:putty";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803871";


if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_bugtraq_id(61645, 61649, 61644, 61599);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-21 11:16:36 +0530 (Wed, 21 Aug 2013)");
  script_name("PuTTY Multiple Integer Overflow Vulnerabilities (Windows)");

  tag_summary =
"The host is installed with PuTTY and is prone to multiple integer overflow
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple Integer overflow errors due to,
- Improper processing of public-key signatures.
- Improper validation of DSA signatures in the 'modmul()' function
  (putty/sshbn.c)
- Not removing sensitive data stored in the memory after it is no longer
  needed.
- Input is not properly validated when handling negative SSH handshake
  message lengths in the getstring() function in sshrsa.c and sshdss.c.";

  tag_impact =
"Successful exploitation will allow attackers to cause heap-based buffer
overflows, resulting in a denial of service or potentially allowing the
execution of arbitrary code.";

  tag_affected =
"PuTTY version before 0.63 on Windows";

  tag_solution =
"Upgrade to version 0.63 or later,
For updates refer to http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/96210");
  script_xref(name : "URL" , value : "http://www.osvdb.com/96080");
  script_xref(name : "URL" , value : "http://www.osvdb.com/96081");
  script_xref(name : "URL" , value : "http://www.osvdb.com/95970");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54354");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q3/289");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q3/291");
  script_xref(name : "URL" , value : "http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html");
  script_summary("Check for the vulnerable version of PuTTy on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_putty_version.nasl");
  script_mandatory_keys("PuTTY/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get version from KB
puttyVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!puttyVer){
  exit(0);
}

## Check for putty version
if(version_is_less(version:puttyVer, test_version:"0.63"))
{
  security_hole(0);
  exit(0);
}
