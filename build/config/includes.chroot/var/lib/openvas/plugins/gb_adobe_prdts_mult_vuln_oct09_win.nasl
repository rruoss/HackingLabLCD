###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_oct09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Reader/Acrobat Multiple Vulnerabilities - Oct09 (Win)
#
# Authors:
# Nikta MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  write arbitrary files or folders to the filesystem, escalate local privileges,
  or cause a denial of service on an affected system by tricking the user to
  open a malicious PDF document.
  Impact Level: Application/System";
tag_summary = "This host has Adobe Reader/Acrobat installed which is/are prone
  to multiple vulnerabilities.";

tag_affected = "Adobe Reader and Acrobat version 7.x before 7.1.4, 8.x before 8.1.7
  and 9.x before 9.2 on Windows.";
tag_insight = "For more information about the vulnerabilities, refer to the links mentioned
  below.";
tag_solution = "Upgrade to Adobe Acrobat and Reader versions 9.2, 8.1.7, or 7.1.4
  For updates refer to http://www.adobe.com/downloads/";

if(description)
{
  script_id(800957);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2982",
                "CVE-2009-2983", "CVE-2009-2984", "CVE-2009-2985", "CVE-2009-2986",
                "CVE-2009-2987", "CVE-2009-2988", "CVE-2009-2989", "CVE-2009-2990",
                "CVE-2009-2991", "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994",
                "CVE-2009-2995", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998",
                "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3460");
  script_bugtraq_id(36686, 36687, 36688, 36691, 36667, 36690, 36680, 36682, 36693,
                    36665, 36669, 36689, 36694, 36681, 36671, 36678, 36677, 36600,
                    36638);
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities - Oct09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36983");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53691");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2851");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2898");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1023007.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-15.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Reader/Win/Ver", "Adobe/Acrobat/Win/Ver");
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

# Check for Adobe Reader version prior to 9.2 or 8.1.7 or 7.1.4
readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer)
{
  if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.3")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.6")||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.3"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Reader version prior to 9.2 or 8.1.7 or 7.1.4
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  if(version_in_range(version:acrobatVer, test_version:"7.0", test_version2:"7.1.3")||
     version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.1.6")||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.1.3")){
    security_hole(0);
  }
}
