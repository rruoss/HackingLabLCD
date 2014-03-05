###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_mult_vuln_nov09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Seamonkey Multiple Vulnerabilities Nov-09 (Win)
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
tag_impact = "Successful exploitation will let attacker to disclose sensitive information,
  bypass certain security restrictions, manipulate certain data, or compromise
  a user's system.
  Impact Level: Application/System";
tag_affected = "Mozilla Seamonkey version prior to 2.0 on Windows.";
tag_insight = "Muliple flaw are due to following errors,
  - When parsing regular expressions used in Proxy Auto-configuration. This can
    be exploited to cause a crash or potentially execute arbitrary code via
    specially crafted configured PAC files.
  - When processing GIF color maps can be exploited to cause a heap based buffer
    overflow and potentially execute arbitrary code via a specially crafted GIF
    file.
  - An error when downloading files can be exploited to display different file
    names in the download dialog title bar and download dialog body. This can
    be exploited to obfuscate file names via a right-to-left override character
    and potentially trick a user into running an executable file.";
tag_solution = "Upgrade to Seamonkey version 2.0
  http://www.seamonkey-project.org/releases";
tag_summary = "This host is installed with Mozilla Seamonkey browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801136);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3376");
  script_bugtraq_id(36856, 36855, 36867);
  script_name("Mozilla Seamonkey Multiple Vulnerabilities Nov-09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-35/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-55.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-56.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_require_keys("Seamonkey/Win/Ver");
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

smVer = get_kb_item("Seamonkey/Win/Ver");
if(!smVer){
  exit(0);
}

# Check for Seamonkey version < 2.0
if(version_is_less(version:smVer, test_version:"2.0")){
  security_hole(0);
}
