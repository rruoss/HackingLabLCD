###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_java_10_6_upd_10.nasl 12 2013-10-27 11:15:33Z jan $
#
# Java for Mac OS X 10.6 Update 10
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
tag_impact = "Has no impact and remote attack vectors.
  Impact Level: Application";
tag_affected = "Java for Mac OS X v10.6.8 or Mac OS X Server v10.6.8";
tag_insight = "Unspecified vulnerability in the JRE component related to AWT sub-component.";
tag_solution = "Upgrade to Java for Mac OS X 10.6 Update 10,
  For updates refer to http://support.apple.com/kb/HT5473";
tag_summary = "This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 10.";

if(description)
{
  script_id(803029);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-21 11:04:53 +0530 (Fri, 21 Sep 2012)");
  script_name("Java for Mac OS X 10.6 Update 10");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84980");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5473");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50133");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027458");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Checks for existence of Java for Mac OS X 10.6 Update 10");
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
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    ## Check for the security update
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6", diff:"10"))
    {
      log_message(data:desc);
      exit(0);
    }
  }
}
