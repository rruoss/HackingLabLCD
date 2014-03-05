###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_int_overflow_vuln_lin_jan12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)
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
tag_impact = "Successful exploitation will allows the attackers to execute arbitrary code
  via unspecified vectors.
  Impact Level: Application";
tag_affected = "Adobe Reader version 9.x before 9.4.6 on Linux.";
tag_insight = "The flaw is due to an integer overflow error, which allows the
  attackers to execute arbitrary code via unspecified vectors.";
tag_solution = "Upgrade Adobe Reader to 9.4.6 or later,
  For updates refer to http://www.adobe.com/";
tag_summary = "This host is installed with Adobe Reader and are prone to
  integer overflow vulnerability.";

if(description)
{
  script_id(802421);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-4374");
  script_bugtraq_id(51557);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:55:01 +0530 (Mon, 23 Jan 2012)");
  script_name("Adobe Reader Integer Overflow Vulnerability - Jan 12 (Linux)");
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
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4374");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name : "URL" , value : "http://people.canonical.com/~ubuntu-security/cve/2011/CVE-2011-4374.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get KB for Adobe Reader
readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(readerVer != NULL)
{
  ## Check for Adobe Reader versions 9.x and 9.4.5
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.5")){
    security_hole(0);
  }
}
