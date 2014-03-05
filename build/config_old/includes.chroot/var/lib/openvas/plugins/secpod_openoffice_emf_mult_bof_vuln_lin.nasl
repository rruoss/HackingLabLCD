###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_emf_mult_bof_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenOffice EMF Files Multiple Buffer Overflow Vulnerabilities (Linux)
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
tag_impact = "Successful remote exploitation could result in arbitrary code execution.
  Impact Level: Application";
tag_affected = "OpenOffice 2.x and 3.x before 3.0.1 on Linux.";
tag_insight = "The Multiple flaws are due to buffer overflow error in cppcanvas/source/
  mtfrenderer/emfplus.cxx' when processing crafted EMF+ files.";
tag_solution = "Upgrade to OpenOffice 3.0.1 or later.
  http://www.openoffice.org/";
tag_summary = "The host has OpenOffice installed and is prone to Multiple Buffer
  Overflow vulnerabilities.";


if(description)
{
  script_id(900955);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2140");
  script_name("OpenOffice EMF Files Multiple Buffer Overflow Vulnerabilities (Linux)");
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
  script_summary("Check for the version of OpenOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_lin.nasl");
  script_require_keys("OpenOffice/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&amp;m=125258116800739&amp;w=2");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&amp;m=125265261125765&amp;w=2");
  exit(0);
}


include("version_func.inc");

openVer = get_kb_item("OpenOffice/Linux/Ver");
if(!openVer){
  exit(0);
}

if(openVer =~ "^(2|3)\..*")
{
  if(version_is_less(version:openVer, test_version:"3.0.1")){
    security_hole(0);
  }
}
