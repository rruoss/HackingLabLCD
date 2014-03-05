###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerzip_insecure_lib_load_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PowerZip Insecure Library Loading Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code or cause a denial of service condition.
  Impact Level: Application";
tag_affected = "PowerZip Version 7.21 and prior.";
tag_insight = "This flaw is due to the application insecurely loading certain
  external libraries from the current working directory, which could allow
  attackers to execute arbitrary code by tricking a user into opening a file
  from a  network share.";
tag_solution = "No solution or patch is available as of 01st August 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.powerzip.biz/";
tag_summary = "This host is installed with PowerZip and is prone to insecure
  library loading vulnerability.";

if(description)
{
  script_id(802312);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PowerZip Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=172");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_PowerZip_ILL_Vuln.txt");

  script_description(desc);
  script_summary("Check for the version of PowerZip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_powerzip_detect.nasl");
  script_require_keys("PowerZip/Ver");
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

## Get version from KB
pzipver = get_kb_item("PowerZip/Ver");

if(!pzipver){
  exit(0);
}

## Check for PowerZip version less than or equal to 7.21
if(version_is_less_equal(version:pzipver, test_version:"7.21")){
  security_hole(0);
}
