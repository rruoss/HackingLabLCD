###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_powerzip_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PowerZip Stack Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes
  via specially  crafted archive 'zip' files.

  Impact level: System/Application";

tag_affected = "PowerZip Version 7.20 or prior.";
tag_insight = "Flaw is due to improper sanitization check for the compressed archive
  'zip' file and may lead to stack based buffer overflow.";
tag_solution = "No solution or patch is available as of 31st March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.powerzip.biz/default.aspx";
tag_summary = "This host is running PowerZip and is prone to Stack Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(900491);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1059");
  script_name("PowerZip Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8180");

  script_description(desc);
  script_summary("Check for the version of PowerZip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_powerzip_detect.nasl");
  script_require_keys("PowerZip/Ver");
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

zipVer = get_kb_item("PowerZip/Ver");
if(zipVer != NULL)
{
  # Grep for PowerZip version 7.20 or prior
  if(version_is_less_equal(version:zipVer, test_version:"7.20")){
    security_hole(0);
  }
}
