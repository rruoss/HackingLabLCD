###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swftools_mult_int_overflow_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# SWFTools Multiple Integer Overflow Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to cause a heap-based
  buffer overflow via specially crafted JPEG and PNG images.
  Impact Level: Application.";
tag_affected = "SWFTools version 0.9.1 and prior.";

tag_insight = "The flaws are due to an error within the 'getPNG()' function in
  'lib/png.c' and 'jpeg_load()' function in 'lib/jpeg.c'.";
tag_solution = "No solution or patch is available as of 18th, August 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.swftools.org/download.html";
tag_summary = "This host is installed with SWFTools and is prone to multiple integer
  overflow vulnerabilities.";

if(description)
{
  script_id(801439);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-1516");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SWFTools Multiple Integer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39970");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-80/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513102/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of SWFTools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_swftools_detect_lin.nasl");
  script_mandatory_keys("login/SSH/success","SWFTools/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

swfVer = get_kb_item("SWFTools/Ver");
if(swfVer != NULL)
{
  ## Check for the SWFTools version <= 0.9.1
  if(version_is_less_equal(version:swfVer, test_version:"0.9.1")){
      security_hole(0);
  }
}
ssh_close_connection();
