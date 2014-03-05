###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mult_dos_vuln02_jun13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# ImageMagick Multiple Denial of Service Vulnerabilities - 02 June13 (Windows)
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
tag_impact = "Successful exploitation will allow a context-dependent attacker to cause
  denial of service result in loss of availability for the application.
  Impact Level: Application";

tag_affected = "ImageMagick version 6.7.5-7 and earlier on Windows.";
tag_insight = "Multiple flaw is due to,
  - Error when parsing an IFD with IOP tag offsets pointing to the start
    of the IFD.
  - Improper sanitation of user supplied input when parsing offset and
    count values of the ResolutionUnit tag in EXIF IFD0.";
tag_solution = "Upgrade to ImageMagick version 6.7.5-8 or later.
  http://www.imagemagick.org/script/download.php";
tag_summary = "The host is installed with ImageMagick and is prone to multiple
  denial of service Vulnerabilities.";

if(description)
{
  script_id(803816);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-0248", "CVE-2012-0247");
  script_bugtraq_id(51957);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-24 13:05:53 +0530 (Mon, 24 Jun 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ImageMagick Multiple Denial of Service Vulnerabilities - 02 June13 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/79003");
  script_xref(name : "URL" , value : "http://www.osvdb.com/79004");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027032");
  script_xref(name : "URL" , value : "http://www.cert.fi/en/reports/2012_15/vulnerability595210.html");
  script_xref(name : "URL" , value : "http://www.imagemagick.org/discourse-server/viewtopic.php?f=4&amp;t=20286");
  script_summary("Check for the vulnerable version of ImageMagick on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("version_func.inc");

imageVer = get_kb_item("ImageMagick/Win/Ver");
if(!imageVer){
  exit(0);
}

if(version_is_less(version:imageVer, test_version:"6.7.5.8"))
{
  security_hole(0);
  exit(0);
}
