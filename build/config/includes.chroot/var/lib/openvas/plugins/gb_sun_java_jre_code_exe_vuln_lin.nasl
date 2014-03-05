###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_jre_code_exe_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java JRE Remote Code Execution Vulnerability (Linux)
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the affected application.
  Impact Level: Application.";
tag_affected = "Sun Java JRE 6 prior to 6 Update 17 on Linux.";
tag_insight = "- An error occurs while using security model permissions when removing
    installer extensions and may allow an untrusted applications to run
    as a trusted application.
  - An error occurs while handling interaction between a signed JAR file
    and a JNLP application or applet.";
tag_solution = "Upgrade to JRE version 6 Update 17
  http://java.sun.com/javase/downloads/index.jsp";
tag_summary = "This host is installed with Sun Java JRE and is prone to Remote
  Code Execution Vulnerability.";

if(description)
{
  script_id(800978);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3866", "CVE-2009-3886");
  script_bugtraq_id(36881);
  script_name("Sun Java JRE Remote Code Execution Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-269870-1");

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
  # Check for 1.6 < 1.6.0_17 (6 Update 17)
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.16")){
    security_hole(0);
  }
}
