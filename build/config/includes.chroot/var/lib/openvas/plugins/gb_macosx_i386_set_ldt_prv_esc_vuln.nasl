###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_i386_set_ldt_prv_esc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apple Mac OS X 'i386_set_ldt()' Privilege Escalation Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code
  with elevated privileges.
  Impact Level: System";
tag_affected = "Mac OS X version 10.6 through 10.6.6
  Mac OS X Server version 10.6 through 10.6.6";
tag_insight = "The flaw is due to a privilege checking issue exists in the
  i386_set_ldt system call, while handling call gates. Which allows local
  users to gain privileges via vectors involving the creation of a call
  gate entry.";
tag_solution = "Upgrade to Mac OS X / Mac OS X Server version 10.6.7 or later,
  For updates refer to http://support.apple.com/kb/HT4581";
tag_summary = "This host is installed with Mac OS X and is prone to privilege
  escalation vulnerability.";

if(description)
{
  script_id(802259);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2011-0182");
  script_bugtraq_id(46997);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Apple Mac OS X 'i386_set_ldt()' Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4581");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/DL1367");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2011/Mar/msg00006.html");

  script_description(desc);
  script_summary("Check for the version of Mac OS X / Mac OS X Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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


include("version_func.inc");
include("pkg-lib-macosx.inc");

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

## Check for the Mac OS X
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.6")){
    security_hole(0);
  }
}
