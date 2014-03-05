###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_jre_mult_vuln_nov09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java JDK/JRE Multiple Vulnerabilities - Nov09 (LinUx)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation allows remote attacker to execute arbitrary code,
  gain escalated privileges, bypass security restrictions and cause denial
  of service attacks inside the context of the affected system.
  Impact Level: System/Application.";
tag_affected = "Sun Java JDK/JRE 6 prior to 6 Update 17
  Sun Java JDK/JRE 5 prior to 5 Update 22
  Sun Java JDK/JRE 1.4.x prior to 1.4.2_24
  Sun Java JDK/JRE 1.3.x prior to 1.3.1_27 on Linux.";
tag_insight = "Multiple flaws occur due to,
  - Error when decoding 'DER' encoded data and parsing HTTP headers.
  - Error when verifying 'HMAC' digests.
  - Interger overflow error in the 'JPEG JFIF' Decoder while processing
    malicious image files.
  - A buffer overflow error in the 'setDiffICM()' and 'setBytePixels()'
    functions in the Abstract Window Toolkit (AWT).
  - Unspecified error due to improper parsing of color profiles of images.
  - A buffer overflow error due to improper implementation of the
    'HsbParser.getSoundBank()' function.
  - Three unspecified errors when processing audio or image files.";
tag_solution = "Upgrade to JDK/JRE version 6 Update 17 or later,
  http://java.sun.com/javase/downloads/index.jsp
  OR
  Upgrade to JDK/JRE version 5 Update 22
  http://java.sun.com/javase/downloads/index_jdk5.jsp
  OR
  Upgrade to JDK/JRE version 1.4.2_24
  http://java.sun.com/j2se/1.4.2/download.html
  OR
  Upgrade to JDK/JRE version 1.3.1_27
  http://java.sun.com/j2se/1.3/download.html";
tag_summary = "This host is installed with Sun Java JDK/JRE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800975);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3877", "CVE-2009-3876", "CVE-2009-3875", "CVE-2009-3873",
                "CVE-2009-3874", "CVE-2009-3872", "CVE-2009-3871", "CVE-2009-3869",
                "CVE-2009-3868", "CVE-2009-3867");
  script_bugtraq_id(36881);
  script_name("Sun Java JDK/JRE Multiple Vulnerabilities - Nov09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37231");
  script_xref(name : "URL" , value : "http://java.sun.com/javase/6/webnotes/6u17.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3131");

  script_description(desc);
  script_summary("Check for the version of Sun Java JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_require_keys("Sun/Java/JRE/Linux/Ver");
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

jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");
if(!jreVer){
  exit(0);
}

jreVer = ereg_replace(pattern:"_", string:jreVer, replace: ".");
jreVer = ereg_replace(pattern:"-b[0-9][0-9]", string:jreVer, replace:"");
if(jreVer)
{
  # Check for 1.3 < 1.3.1_27, 1.4 < 1.4.2_24, 1.5 < 1.5.0_22 (5 Update 22),
  #       and 1.6 < 1.6.0_17 (6 Update 17)
  if(version_in_range(version:jreVer, test_version:"1.3", test_version2:"1.3.1.26")||
     version_in_range(version:jreVer, test_version:"1.4", test_version2:"1.4.2.23")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.21")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.16")){
    security_hole(0);
  }
}
