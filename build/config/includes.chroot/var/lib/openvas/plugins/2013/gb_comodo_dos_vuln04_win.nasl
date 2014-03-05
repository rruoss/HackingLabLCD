###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_dos_vuln04_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Comodo Internet Security Denial of Service Vulnerability-04
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
tag_impact = "Successful exploitation allow attackers to cause denial of service condition.
  Impact Level: Application";

tag_affected = "Comodo Internet Security versions before 3.11.108364.552";
tag_insight = "Flaw related to the antivirus component, triggered when a user opens an
  unspecified malformed packed or compressed file.";
tag_solution = "Upgrade to Comodo Internet Security version 3.11.108364.552 or later,
  For updates refer to http://personalfirewall.comodo.com";
tag_summary = "The host is installed with Comodo Internet Security and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(803691);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2009-5124", "CVE-2009-5123");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-05 16:23:15 +0530 (Fri, 05 Jul 2013)");
  script_name("Comodo Internet Security Denial of Service Vulnerability-04");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/85207");
  script_xref(name : "URL" , value : "http://www.osvdb.org/85208");
  script_xref(name : "URL" , value : "http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Comodo Internet Security");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
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

# Variable Initialization
Ver ="";

# Get the version from KB
Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

# Check for Comodo Internet Security Version
if(Ver)
{
  if(version_is_less(version:Ver, test_version:"3.11.108364.552")){
    security_warning(0);
    exit(0);
  }
}
