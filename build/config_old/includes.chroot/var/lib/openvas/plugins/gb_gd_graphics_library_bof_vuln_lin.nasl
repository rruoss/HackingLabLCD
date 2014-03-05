###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gd_graphics_library_bof_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# GD Graphics Library '_gdGetColors()' Buffer Overflow Vulnerability (Linux)
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
tag_impact = "Successful exploitation could allow attackers to potentially compromise a
  vulnerable system.
  Impact Level: System";
tag_affected = "GD Graphics Library version 2.x on Linux.";
tag_insight = "The flaw is due to error in '_gdGetColors' function in gd_gd.c which fails to
  check certain colorsTotal structure member, whicn can be exploited to cause
  buffer overflow or buffer over-read attacks via a crafted GD file.";
tag_solution = "No solution or patch is available as of 23rd October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.boutell.com/gd/";
tag_summary = "The host is installed with GD Graphics Library and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(801122);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3546");
  script_bugtraq_id(36712);
  script_name("GD Graphics Library '_gdGetColors()' Buffer Overflow Vulnerability (Linux)");
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


  script_description(desc);
  script_summary("Check for the version of GD Graphics Library");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_gd_graphics_library_detect_lin.nasl");
  script_require_keys("GD-Graphics-Lib/Lin/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37069/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2929");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&amp;m=125562113503923&amp;w=2");
  exit(0);
}


gdVer = get_kb_item("GD-Graphics-Lib/Lin/Ver");

# Check GD Graphics Library version 2.x
if(gdVer =~ "^2\..*"){
  security_hole(0);
}
