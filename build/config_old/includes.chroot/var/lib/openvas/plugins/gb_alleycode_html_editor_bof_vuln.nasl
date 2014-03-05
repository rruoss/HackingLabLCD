###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alleycode_html_editor_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Alleycode HTML Editor Buffer Overflow Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  compromise a user's system.
  Impact Level: System/Application";
tag_affected = "Alleycode HTML Editor version 2.21 and prior";
tag_insight = "Multiple boundary error exists in the Meta Content Optimizer when displaying
  the content of 'TITLE' or 'META' HTML tags. This can be exploited to cause a
  stack-based buffer overflow via an HTML file defining an overly long 'TITLE'
  tag, 'description' or 'keywords' 'META' tag.";
tag_solution = "No solution or patch is available as of 23rd October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.alleycode.com/";
tag_summary = "This host is installed with Alleycode HTML Editor and is prone to
  Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(801127);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3708", "CVE-2009-3709");
  script_name("Alleycode HTML Editor Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/58649");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36940");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0910-exploits/alleycode-overflow.txt");

  script_description(desc);
  script_summary("Check for the version of Alleycode HTML Editor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_alleycode_html_editor_detect.nasl");
  script_require_keys("Alleycode-HTML-Editor/Ver");
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

aheVer = get_kb_item("Alleycode-HTML-Editor/Ver");
if(!aheVer){
  exit(0);
}

# Check for Alleycode HTML Editor version <= 2.21 (2.2.1)
if(version_is_less_equal(version:aheVer, test_version:"2.2.1")){
  security_hole(0);
}
