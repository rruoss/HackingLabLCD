###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_xml_doc_dos_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer XML Document DoS Vulnerability - Aug09
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
tag_impact = "Successful exploitation could allow remote attackers to cause Denial of
  Service in the context of an affected application.
  Impact Level: Application";
tag_affected = "Internet Explorer version 6.x to 6.0.2900.2180 and 7.x to 7.0.6000.16473";
tag_insight = "The flaw exists via an XML document composed of a long series of start-tags
  with no corresponding end-tags and it leads to CPU consumption.";
tag_solution = "No solution or patch is available as of 07th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/products/default.aspx";
tag_summary = "This host has Internet Explorer installed and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800863);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2668");
  script_name("Microsoft Internet Explorer XML Document DoS Vulnerability - Aug09");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3216/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2009-07/0193.html");

  script_description(desc);
  script_summary("Check for the Version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/EXE/Ver");
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

# Get for Internet Explorer Version
ieVer = get_kb_item("MS/IE/EXE/Ver");

if(!isnull(ieVer))
{
  # Check for IE version 6.0 <= 6.0.2900.2180 or 7.0 <= 7.0.6000.16473
  if(version_in_range(version:ieVer, test_version:"6.0",
                                    test_version2:"6.0.2900.2180")||
     version_in_range(version:ieVer, test_version:"7.0",
                                    test_version2:"7.0.6000.16473")){
    security_hole(0);
  }
}
