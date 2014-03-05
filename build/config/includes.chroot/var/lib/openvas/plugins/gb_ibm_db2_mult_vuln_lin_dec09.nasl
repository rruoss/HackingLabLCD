###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_mult_vuln_lin_dec09.nasl 15 2013-10-27 12:49:54Z jan $
#
# IBM DB2 Multiple Vulnerabilities - Dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation allows the attacker to potentially perform certain
  actions with escalated privileges or to bypass certain security restrictions.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 8 prior to Fixpak 18
  IBM DB2 version 9.1 prior to Fixpak 8
  IBM DB2 version 9.5 prior to Fixpak 4
  IBM DB2 version 9.7 prior to Fixpak 1";
tag_insight = "Multiple flaws are due to:
  - Unspecified error exists related to a table function when the definer
    loses required privileges.
  - Unspecified error that can be exploited to insert, update, or delete rows
    in a table without having required privileges.
  - Unspecified error in the handling of 'SET SESSION AUTHORIZATION' statements.
  - Error in 'DASAUTO' command, it can be run by non-privileged users.";
tag_solution = "Update DB2 8 Fixpak 18 or 9.1 Fixpak 8 or 9.5 Fixpak 4 or 9.7 Fixpak 1 or later.
  For updates refer to http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801071);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4150");
  script_name("IBM DB2 Multiple Vulnerabilities - Dec09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37454");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1023242");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3340");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21403619");

  script_description(desc);
  script_summary("Check for the version of IBM DB2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ibm_db2_detect_linux_900217.nasl");
  script_require_keys("Linux/IBM_db2/Ver");
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

ibmVer = get_kb_item("Linux/IBM_db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 version 8 before FP18, 9.1 before FP8, 9.5 before FP4
# 9.1 FP8 =>9.1.0.8, 9.5 FP4 =>9.5.0.4, 8 FP18 =>8.1.18, 9.7 FP1=> 9.7.0.1
if(version_is_equal(version:ibmVer, test_version:"9.7.0.0")||
   version_in_range(version:ibmVer, test_version:"8.0", test_version2:"8.1.17")||
   version_in_range(version:ibmVer, test_version:"9.1", test_version2:"9.1.0.7")||
   version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.0.3")){
  security_warning(0);
}
