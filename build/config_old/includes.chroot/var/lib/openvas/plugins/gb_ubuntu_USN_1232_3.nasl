###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for xorg-server USN-1232-3
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "USN-1232-1 fixed vulnerabilities in the X.Org X server. A regression was
  found on Ubuntu 10.04 LTS that affected GLX support, and USN-1232-2 was
  released to temporarily disable the problematic security fix. This update
  includes a revised fix for CVE-2010-4818.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly execute arbitrary code
  with root privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-4818)
  
  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly read arbitrary data from
  the X server process. This issue only affected Ubuntu 10.04 LTS.
  (CVE-2010-4819)
  
  Vladz discovered that the X server incorrectly handled lock files. A local
  attacker could use this flaw to determine if a file existed or not.
  (CVE-2011-4028)
  
  Vladz discovered that the X server incorrectly handled setting lock file
  permissions. A local attacker could use this flaw to gain read permissions
  on arbitrary files and view sensitive information. (CVE-2011-4029)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1232-3";
tag_affected = "xorg-server on Ubuntu 10.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-October/001454.html");
  script_id(840775);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1232-3");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4818", "CVE-2010-4819", "CVE-2011-4028", "CVE-2011-4029");
  script_name("Ubuntu Update for xorg-server USN-1232-3");

  script_description(desc);
  script_summary("Check for the Version of xorg-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.6-2ubuntu7.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.9.0-0ubuntu7.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
