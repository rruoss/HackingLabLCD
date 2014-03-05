###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libpng_null_pntr_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# libpng pngwutil.c NULL pointer Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful remote exploitation could result in arbitrary code execution
  on the affected system.
  Impact Level: Application";
tag_affected = "libpng 1.0.41 and prior and 1.2.x to 1.2.33 on Linux.";
tag_insight = "Attackers can set the value of arbitrary memory location to zero via
  vectors involving creation of crafted PNG files with keywords, related
  to an implicit cast of the '\0' character constant to a NULL pointer.";
tag_solution = "Upgrade to libpng 1.0.42 or 1.2.34,
  http://libpng.sourceforge.net/index.html";
tag_summary = "The host has libpng installed and is prone to memory overwrite
  vulnerability.";


if(description)
{
  script_id(900071);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5907");
  script_name("libpng pngwutil.c NULL pointer Vulnerability");
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
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2009/01/09/1");

  script_description(desc);
  script_summary("Check for the version of libpng");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_libpng_detect_lin.nasl");
  script_require_keys("Libpng/Version");
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

pngVer = get_kb_item("Libpng/Version");
if(!pngVer){
  exit(0);
}

if(version_is_less_equal(version:pngVer, test_version:"1.0.41")||
   version_in_range(version:pngVer, test_version:"1.2.0", test_version2:"1.2.33")){
  security_warning(0);
}
