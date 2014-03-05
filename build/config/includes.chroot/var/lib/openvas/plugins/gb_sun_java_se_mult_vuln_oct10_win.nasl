###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_se_mult_vuln_oct10_win.nasl 11742 2010-10-25 15:43:20Z oct$
#
# Oracle Java SE Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to JDK/JRE version 6 Update 22
  http://www.oracle.com/technetwork/java/javase/downloads/index-jsp-138363.html

  or
  Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to manipulate or gain knowledge
  of sensitive information, bypass restrictions, cause a denial of service or
  compromise a vulnerable system.
  Impact Level: System/Application";
tag_affected = "Oracle Java JDK/JRE version 6 Update 21 on windows";
tag_insight = "Multiple flas are caused by errors in the 2D, CORBA, Deployment, JRE,
  Java Web Start, New Java Plug-in, Sound, Deployment Toolkit, JSSE, Kerberos,
  Networking, Swing, and JNDI components.";
tag_summary = "This host is installed with Oracle Java JDK/JRE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801530);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553",
                "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557",
                "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561",
                "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566",
                "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570",
                "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Oracle Java SE Multiple Vulnerabilities (Windows)");
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

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2660");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Oracle Java JDK/JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JDK/Win/Ver", "Sun/Java/JRE/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Get KB for JDK Version On Windows
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  jdkVer = ereg_replace(pattern:"_", string:jdkVer, replace: ".");
  if(jdkVer)
  {
    # Check for 1.6 < 1.6.0_22 (6 Update 22)
    if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.21"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  jreVer = ereg_replace(pattern:"_", string:jreVer, replace: ".");
  if(jreVer)
  {
    # Grep for JRE Version 1.6 < 1.6.0_22 (6 Update 22)
    if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.21")) {
      security_hole(0);
    }
  }
}