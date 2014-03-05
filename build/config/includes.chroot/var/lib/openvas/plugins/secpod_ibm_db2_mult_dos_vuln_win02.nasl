###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_mult_dos_vuln_win02.nasl 15 2013-10-27 12:49:54Z jan $
#
# IBM DB2 Multiple DOS Vulnerabilities (Win)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service or gain elevated privileges.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 8 prior to Fixpak 17
  IBM DB2 version 9.1 prior to Fixpak 5
  IBM DB2 version 9.5 prior to Fixpak 2";
tag_insight = "The flaws are due to,
  - An unspecified error related to the DB2FMP process running
    with OS prvileges.
  - An error in INSTALL_JAR procedure  might allows remote authenticated
    users to create or overwrite arbitrary files via unspecified calls.
  - A boundary error in DAS server code can be exploited to cause a buffer
    overflow via via unspecified vectors.";
tag_solution = "Update DB2 8 Fixpak 17 or 9.1 Fixpak 5 or 9.5 Fixpak 2 or later.
  http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678";
tag_summary = "The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900677);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6821", "CVE-2008-6820","CVE-2008-2154");
  script_bugtraq_id(31058, 35409);
  script_name("IBM DB2 Multiple Vulnerabilities (Win)");

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31787");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jun/1022319.htm");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");

  script_description(desc);
  script_summary("Check for the Version of IBM DB2 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_require_keys("Win/IBM-db2/Ver");
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

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 Products Version 8 before 8 FP17 (8.1.17)-8.1.17.617
# Check for IBM DB2 Products Version 9.1 before 9.1 FP5 (9.1.500)-9.1.500.555
# Check for IBM DB2 Products Version 9.5 before 9.5 FP2 => 9.5.200.315
# IBM DB2 9.1 FP4a =>9.1.401.444
# IBM DB2 9.5 FP1 =>9.5.100.179

if(version_in_range(version:ibmVer, test_version:"8.0",
                   test_version2:"8.1.16")||
   version_in_range(version:ibmVer, test_version:"9.1",
                   test_version2:"9.1.401.444")||
   version_in_range(version:ibmVer, test_version:"9.5",
                   test_version2:"9.5.100.179")){
  security_hole(0);
}
