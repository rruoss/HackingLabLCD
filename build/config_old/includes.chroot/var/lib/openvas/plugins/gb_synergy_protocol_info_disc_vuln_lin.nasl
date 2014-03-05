###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synergy_protocol_info_disc_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Synergy Protocol Information Disclosure Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Synergy Version 1.4";
tag_insight = "The flaw is caused by sending all keystrokes and mouse movements in clear
  text, which allows attacker to eavesdrop on all information passed between
  the multiple computers.";
tag_solution = "No solution or patch is available as of 11th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://synergy-foss.org/download";
tag_summary = "This host is installed with Synergy and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801873);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Synergy Protocol Information Disclosure Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100157/synergy-cleartext.txt");

  script_description(desc);
  script_summary("Check for the version of Synergy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synergy_detect_lin.nasl");
  script_require_keys("Synergy/Lin/Ver");
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
ver = get_kb_item("Synergy/Lin/Ver");
if(ver)
{
  ## Check for Synergy Version 1.4
  if(version_in_range(version:ver, test_version:"1.4.0", test_version2:"1.4.2")){
    security_warning(0);
  }
}
