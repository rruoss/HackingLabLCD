###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_domain_policy_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Internet Explorer Domain Policy Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to disclosure the information
  when a user views a specially crafted webpage.
  Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x on Windows XP and 2003";
tag_insight = "The flaw due to error in UNC share pathname in SRC attribute of a SCRIPT
  element, which allows attackers to obtain sensitive information about the
  existence of files and read certain data from files.";
tag_solution = "Upgrade to Internet Explorer 10.
  For updates refer to http://ie.microsoft.com/testdrive/info/downloads";
tag_summary = "This host is installed with Microsoft Internet Explorer and is
  prone to domain policy bypass vulnerability.";

if(description)
{
  script_id(803302);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6502");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-01 11:11:56 +0530 (Fri, 01 Feb 2013)");
  script_name("Microsoft Internet Explorer Domain Policy Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.nsfocus.com/en/2012/advisories_1228/119.html");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2012-6502");

  script_description(desc);
  script_summary("Check the vulnerable version of Internet Explorer on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("secpod_reg.inc");

# Variables Initialization
ieVer = "";

# Check for product Internet Explorer
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3) > 0 )
{
  if(ieVer =~ "^(6|7|8|9)"){
    security_warning(0);
  }
}
