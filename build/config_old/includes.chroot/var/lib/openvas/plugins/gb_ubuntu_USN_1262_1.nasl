###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for lightdm USN-1262-1
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "It was discovered that Light Display Manager incorrectly handled privileges
  when reading .dmrc files. A local attacker could exploit this issue to read
  arbitrary configuration files, bypassing intended permissions.
  (CVE-2011-3153)

  It was discovered that Light Display Manager incorrectly handled links when
  adjusting permissions on .Xauthority files. A local attacker could exploit
  this issue to access arbitrary files, and possibly obtain increased
  privileges. In the default Ubuntu installation, this would be prevented
  by the Yama link restrictions. (CVE-2011-4105)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1262-1";
tag_affected = "lightdm on Ubuntu 11.10";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-November/001480.html");
  script_id(840953);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-16 10:53:22 +0530 (Fri, 16 Mar 2012)");
  script_cve_id("CVE-2011-3153", "CVE-2011-4105");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_xref(name: "USN", value: "1262-1");
  script_name("Ubuntu Update for lightdm USN-1262-1");

  script_description(desc);
  script_summary("Check for the Version of lightdm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"liblightdm-gobject-1-0", ver:"1.0.6-0ubuntu1.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liblightdm-qt-1-0", ver:"1.0.6-0ubuntu1.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"lightdm", ver:"1.0.6-0ubuntu1.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
