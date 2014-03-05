###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_jre_mult_code_exec_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle Java SE JRE Multiple Remote Code Execution Vulnerabilities - (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to bypass SecurityManager
  restrictions and execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Oracle Java SE versions 7 Update 6 and earlier";
tag_insight = "- SecurityManager restrictions using
    'com.sun.beans.finder.ClassFinder.findClass' with the forName method to
    access restricted classes and 'reflection with a trusted immediate caller'
    to access and modify private fields.
  - Multiple unspecified vulnerabilities in the JRE component related to
    Beans sub-component.";
tag_solution = "Apply the patch from below link
  http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html";
tag_summary = "This host is installed with Oracle Java SE JRE and is prone to
  multiple remote code execution vulnerabilities.";

if(description)
{
  script_id(803020);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4681", "CVE-2012-1682", "CVE-2012-3136");
  script_bugtraq_id(53135, 55336, 55337);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-03 11:54:23 +0530 (Mon, 03 Sep 2012)");
  script_name("Oracle Java SE JRE Multiple Remote Code Execution Vulnerabilities - (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84981");
  script_xref(name : "URL" , value : "http://www.osvdb.org/84982");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50133");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027458");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html");

  script_description(desc);
  script_summary("Check for the version of Sun Java SE JRE on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver");
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

## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ## Check for Oracle Java SE versions 7 Update 6 and earlier,
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.6")){
    security_hole(0);
  }
}
