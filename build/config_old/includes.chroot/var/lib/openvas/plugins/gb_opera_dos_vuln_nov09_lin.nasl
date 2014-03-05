###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_dos_vuln_nov09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Opera Denial Of Service Vulnerability - Nov09 (Linux)
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
tag_impact = "Successful attackers may leads to Denial of Service on the affected application.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.01 on Linux.";
tag_insight = "An error when processing domain names can be exploited to cause a memory
  corruption.";
tag_solution = "Upgrade to Opera version 10.01 or later
  http://www.opera.com/browser/download/";
tag_summary = "This host is installed with Opera Web Browser and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(801141);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3831");
  script_bugtraq_id(36850);
  script_name("Opera Denial Of Service Vulnerability - Nov09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37182");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/938/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unix/1001/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3073");

  script_description(desc);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
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

operaVer = get_kb_item("Opera/Linux/Version");
if(operaVer)
{
  # Check for Opera Version < 10.01
  if(version_is_less(version:operaVer, test_version:"10.01")){
    security_hole(0);
  }
}
