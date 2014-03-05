###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ideal_administrator_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# IDEAL Administration '.ipj' File Processing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code or
  compromise a user's system.

  Impact level: System.";

tag_affected = "IDEAL Administration 9.7.1 and prior.";
tag_insight = "This flaw is due to a boundary error in the processing of Ideal Project
  Files ('.ipj'). This can be exploited to cause a stack based buffer overflow
  when a user is tricked into opening a specially crafted '.ipj' file through
  the application.";
tag_solution = "No solution or patch is available as of 11th December, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For further information refer, http://www.pointdev.com/en/download/index.php";
tag_summary = "This host is installed with IDEAL Administration and is prone to
  Buffer Overflow Vulnerability.";

if(description)
{
  script_id(801089);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4265");
  script_name("IDEAL Administration '.ipj' File Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://freetexthost.com/abydoz3jwu");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37572");
  script_xref(name : "URL" , value : "http://pocoftheday.blogspot.com/2009/12/ideal-administration-2009-v97-local.html");

  script_description(desc);
  script_summary("Check for the version of IDEAL Administration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ideal_administrator_detect.nasl");
  script_require_keys("IDEAL/Admin/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

# Check for IDEAL Administration 2009 (v9.7.1) and prior
if(iaVer = get_kb_item("IDEAL/Admin/Ver"))
{
  if(version_is_less_equal(version:iaVer, test_version:"9.7.1")){
    security_hole(0);
  }
}
