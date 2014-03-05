###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_se_mult_vuln_nov09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java SE Multiple Vulnerabilities - Nov09 (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_affected = "Sun Java SE 6 prior to 6 Update 17
  Sun Java SE 5 prior to 5 Update 22 on Windows.";
tag_insight = "Multiple flaws occur due to:
  - Directory traversal vulnerabilty in 'ICC_Profile.getInstance' method.
  - Unspecified error in TrueType font parsing functionality.
  - When a non-English version of Windows is used, the Java Update functionality
    does not retrieve available new JRE versions.
  - Failure to clone arrays that are returned by the 'getConfigurations()'
    function in X11 and Win32GraphicsDevice.
  - The Abstract Window Toolkit (AWT) does not properly restrict the objects
    that may be sent to loggers.
  - Information leak occurs as the application does not prevent the existence
    of children of a resurrected ClassLoader.
  - Multiple unspecified errors in the Swing implementation.
  - The 'TimeZone.getTimeZone' method allows users to probe for the existence
    of local files via vectors related to handling of zoneinfo.
  - Error during parsing of BMP files containing UNC ICC links.";
tag_solution = "Upgrade to JRE version 6 Update 17 or later.
  http://java.sun.com/javase/downloads/index.jsp
  OR
  Upgrade to JRE version 5 Update 22
  http://java.sun.com/javase/downloads/index_jdk5.jsp";
tag_summary = "This host is installed with Sun Java SE and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900978);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3864", "CVE-2009-3879",
                "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883",
                "CVE-2009-3884", "CVE-2009-3885");
  script_bugtraq_id(36881);
  script_name("Sun Java SE Multiple Vulnerabilities - Nov09 (Win)");
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
  script_xref(name : "URL" , value : "http://java.sun.com/javase/6/webnotes/6u17.html");
  script_xref(name : "URL" , value : "http://java.sun.com/j2se/1.5.0/ReleaseNotes.html");

  script_description(desc);
  script_summary("Check for the version of Sun Java JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver", "Sun/Java/JDK/Win/Ver");
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

# Check for JRE version

i = 0;
if(jreVer = get_kb_item("Sun/Java/JRE/Win/Ver")) {
  version[i] = jreVer;
  i++;
}

if(jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver")) {
  version[i] = jdkVer;
}

foreach ver (version)
{
  if(ver)
  {
    ver = ereg_replace(pattern:"_", string:ver, replace: ".");
    # Check for 1.6 < 1.6.0_17 (6 Update 17) and 1.5 < 1.5.0_22 (5 Update 22)
    if(version_in_range(version:ver, test_version:"1.5", test_version2:"1.5.0.21")||
       version_in_range(version:ver, test_version:"1.6", test_version2:"1.6.0.16"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
