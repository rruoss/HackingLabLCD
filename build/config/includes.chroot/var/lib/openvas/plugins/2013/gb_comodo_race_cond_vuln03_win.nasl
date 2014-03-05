###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_race_cond_vuln03_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Comodo Internet Security Race Condition Vulnerability-03
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
tag_impact = "Successful exploitation allows local attacker to bypass certain security
  features.
  Impact Level: System/Application";

tag_affected = "Comodo Internet Security versions before 4.1.149672.916";
tag_insight = "Flaw due to improper implementation of security checks in certain kernel
  hooks.";
tag_solution = "Upgrade to Comodo Internet Security version 4.1.149672.916 or later,
  For updates refer to http://personalfirewall.comodo.com";
tag_summary = "The host is installed with Comodo Internet Security and is prone
  to race condition vulnerability.";

if(description)
{
  script_id(803686);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2010-5157");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-05 15:35:47 +0530 (Fri, 05 Jul 2013)");
  script_name("Comodo Internet Security Race Condition Vulnerability-03");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/65254");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40094");
  script_xref(name : "URL" , value : "http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Comodo Internet Security");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

# Variable Initialization
Ver ="";

# Get the version from KB
Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

# Check for Comodo Internet Security Version
if(Ver)
{
  if(version_is_less(version:Ver, test_version:"4.1.149672.916")){
    security_hole(0);
    exit(0);
  }
}
