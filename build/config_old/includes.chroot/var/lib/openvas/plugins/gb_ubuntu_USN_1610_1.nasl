###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1610-1
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
tag_insight = "Pablo Neira Ayuso discovered a flaw in the credentials of netlink messages.
  An unprivileged local attacker could exploit this by getting a netlink
  based service, that relies on netlink credentials, to perform privileged
  actions.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1610-1";
tag_affected = "linux on Ubuntu 12.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001869.html");
  script_id(841192);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-16 09:47:50 +0530 (Tue, 16 Oct 2012)");
  script_cve_id("CVE-2012-3520");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_xref(name: "USN", value: "1610-1");
  script_name("Ubuntu Update for linux USN-1610-1");

  script_description(desc);
  script_summary("Check for the Version of linux");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-generic", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-generic-pae", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-highbank", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-omap", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-powerpc-smp", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-powerpc64-smp", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-32-virtual", ver:"3.2.0-32.51", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
