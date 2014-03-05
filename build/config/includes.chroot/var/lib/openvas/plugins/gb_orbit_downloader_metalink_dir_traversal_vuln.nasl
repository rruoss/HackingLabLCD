###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orbit_downloader_metalink_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Orbit Downloader metalink 'name' Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to download files to directories
  outside of the intended download directory via directory traversal attacks.
  Impact Level: Application";
tag_affected = "Orbit Downloader Version 3.0.0.4 and 3.0.0.5.";
tag_insight = "The flaw is due to an error in the handling of metalink files. The 'name'
  attribute of a 'file' element in a metalink file is not properly sanitised.";
tag_solution = "No solution or patch is available as of 1st June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.orbitdownloader.com/download.htm";
tag_summary = "This host is installed with Orbit Downloader and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(801214);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2104");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Orbit Downloader metalink 'name' Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511348/100/100/threaded");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-73/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39527");

  script_description(desc);
  script_summary("Check for the version of Orbit Downloader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_orbit_downloader_detect.nasl");
  script_require_keys("OrbitDownloader/Ver");
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
ver = get_kb_item("OrbitDownloader/Ver");

if(ver){
  ##Grep for Orbit Downloader versions 3.0.0.4 and 3.0.0.5
  if(version_is_equal(version:ver, test_version:"3.0.0.4") ||
     version_is_equal(version:ver, test_version:"3.0.0.5") ){
    security_warning(0);
  }
}
