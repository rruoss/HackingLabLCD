###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-backport-natty USN-1440-1
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
tag_insight = "A flaw was found in the Linux's kernels ext4 file system when mounted with
  a journal. A local, unprivileged user could exploit this flaw to cause a
  denial of service. (CVE-2011-4086)

  Sasha Levin discovered a flaw in the permission checking for device
  assignments requested via the kvm ioctl in the Linux kernel. A local user
  could use this flaw to crash the system causing a denial of service.
  (CVE-2011-4347)

  Stephan B&#195;&#164;rwolf discovered a flaw in the KVM (kernel-based virtual
  machine) subsystem of the Linux kernel. A local unprivileged user can crash
  use this flaw to crash VMs causing a deny of service. (CVE-2012-0045)

  A flaw was discovered in the Linux kernel's cifs file system. An
  unprivileged local user could exploit this flaw to crash the system leading
  to a denial of service. (CVE-2012-1090)

  H. Peter Anvin reported a flaw in the Linux kernel that could crash the
  system. A local user could exploit this flaw to crash the system.
  (CVE-2012-1097)

  A flaw was discovered in the Linux kernel's cgroups subset. A local
  attacker could use this flaw to crash the system. (CVE-2012-1146)

  A flaw was found in the Linux kernel's ext4 file system when mounting a
  corrupt filesystem. A user-assisted remote attacker could exploit this flaw
  to cause a denial of service. (CVE-2012-2100)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1440-1";
tag_affected = "linux-lts-backport-natty on Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-May/001681.html");
  script_id(841004);
  script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-11 11:02:36 +0530 (Fri, 11 May 2012)");
  script_cve_id("CVE-2011-4086", "CVE-2011-4347", "CVE-2012-0045", "CVE-2012-1090",
                "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-2100");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1440-1");
  script_name("Ubuntu Update for linux-lts-backport-natty USN-1440-1");

  script_description(desc);
  script_summary("Check for the Version of linux-lts-backport-natty");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic", ver:"2.6.38-15.59~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic-pae", ver:"2.6.38-15.59~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-server", ver:"2.6.38-15.59~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-virtual", ver:"2.6.38-15.59~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
