###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_dec11_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Opera Multiple Vulnerabilities - December11 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial of service condition.
  Impact Level: Application";
tag_affected = "Opera version before 11.60";
tag_insight = "Multiple flaws are due to
  - An improper handling of the number of .(dot) characters that conventionally
    exist in domain names of different top-level domains.
  - An implementation errors in the 'JavaScript' engine, 'Web Workers' and 'in'
    operator.
  - An error when handling certificate revocation related to 'corner cases'.
  - An error in Dragonfly in opera.";
tag_solution = "Upgrade to the Opera version 11.60 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802361);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2011-4684",
                "CVE-2011-4685", "CVE-2011-4686", "CVE-2011-4687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 15:13:28 +0530 (Fri, 09 Dec 2011)");
  script_name("Opera Multiple Vulnerabilities - December11 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1003/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1005/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1160/");

  script_description(desc);
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version < 11.60
if(version_is_less(version:operaVer, test_version:"11.60")){
  security_hole(0);
}
