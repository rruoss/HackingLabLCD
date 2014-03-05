###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_java_10_5_upd_10.nasl 13 2013-10-27 12:16:33Z jan $
#
# Java for Mac OS X 10.5 Update 10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.
  Impact Level: System/Application";
tag_affected = "Java for Mac OS X v10.5.8 and Mac OS X Server v10.5.8";
tag_insight = "For more information on the vulnerabilities refer the below links.";
tag_solution = "Upgrade to Java for Mac OS X 10.5 Update 10,
  For updates refer to http://support.apple.com/kb/HT4739";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.5 Update 10.";

if(description)
{
  script_id(902553);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0862", "CVE-2011-0863",
                "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868",
                "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0873");
  script_bugtraq_id(48137, 48138, 48140, 48144, 48145, 48147, 48148, 48149);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Java for Mac OS X 10.5 Update 10");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4739");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Jun/msg00002.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Checks for existence of Java for Mac OS X 10.5 Update 10");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("pkg-lib-macosx.inc");
include("version_func.inc");

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.5.8"))
  {
    ## Check for the security update
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.5Update", diff:"10"))
    {
      security_hole(0);
      exit(0);
    }
  }
}