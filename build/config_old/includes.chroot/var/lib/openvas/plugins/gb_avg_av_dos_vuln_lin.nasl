###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_av_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Denial of Service vulnerability in AVG Anti-Virus (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application or even can cause denial of service.
  Impact Level: Application";
tag_affected = "AVG Anti-Virus version 7.5.51 and prior on Linux.";
tag_insight = "The flaw is caused by a memory corruption error when the scan engine processes
  malformed UPX files.";
tag_solution = "No solution or patch is available as of 17th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.avg.com";
tag_summary = "This host is installed with AVG Anti-Virus and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(800395);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6662");
  script_bugtraq_id(32749);
  script_name("Denial of Service vulnerability in AVG Anti-Virus (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47254");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/3461");

  script_description(desc);
  script_summary("Check for the version of AVG Anti-Virus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avg_av_detect_lin.nasl");
  script_require_keys("AVG/AV/Linux/Ver");
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

avgVer = get_kb_item("AVG/AV/Linux/Ver");
if(!avgVer){
  exit(0);
}

# Grep for AVG Anti-Virus version < 7.5.51
if(version_is_less_equal(version:avgVer, test_version:"7.5.51")){
  security_warning(0);
}
