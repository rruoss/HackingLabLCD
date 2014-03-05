###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_dos_vuln_july13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Comodo Internet Security Denial of Service Vulnerability July 13
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
tag_impact = "Successful exploitation allow attackers to cause denial of service condition
  via crafted Portable Executable (PE) file.
  Impact Level: Application";

tag_affected = "Comodo Internet Security versions before 5.10.228257.2253 on Windows 7 x64";
tag_insight = "Issue is triggered when handling executables with that contain kernels with
  imagebase values.";
tag_solution = "Upgrade to Comodo Internet Security version 5.10.228257.2253 or later,
  For updates refer to http://www.comodo.com/home/internet-security/free-internet-security.php";
tag_summary = "The host is installed with Comodo Internet Security and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(803695);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-2273");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-16 12:47:17 +0530 (Tue, 16 Jul 2013)");
  script_name("Comodo Internet Security Denial of Service Vulnerability July 13");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/81269");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Apr/13");
  script_xref(name : "URL" , value : "http://www.comodo.com/home/download/release-notes.php?p=anti-malware");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Comodo Internet Security");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
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
include("secpod_reg.inc");

# Variable Initialization
Ver ="";

## Check for OS
if(hotfix_check_sp(win7x64:2) <= 0){
  exit(0);
}

# Get the version from KB
Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

# Check for Comodo Internet Security Version
if(Ver)
{
  if(version_is_less(version:Ver, test_version:"5.10.228257.2253")){
    security_warning(0);
    exit(0);
  }
}
