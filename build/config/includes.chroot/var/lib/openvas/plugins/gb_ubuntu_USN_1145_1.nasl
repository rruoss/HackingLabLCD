###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for qemu-kvm USN-1145-1
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
tag_insight = "It was discovered that QEMU did not properly perform validation of I/O
  operations from the guest which could lead to heap corruption. An attacker
  could exploit this to cause a denial of service of the guest or possibly
  execute code with the privileges of the user invoking the program.
  (CVE-2011-1750)

  Nelson Elhage discoverd that QEMU did not properly handle memory when
  removing ISA devices. An attacker could exploit this to cause a denial of
  service of the guest or possibly execute code with the privileges of the
  user invoking the program. (CVE-2011-1751)
  
  When using QEMU with libvirt or virtualization management software based on
  libvirt such as Eucalyptus and OpenStack, QEMU guests are individually isolated
  by an AppArmor profile by default in Ubuntu.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1145-1";
tag_affected = "qemu-kvm on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-June/001349.html");
  script_id(840677);
  script_tag(name:"cvss_base", value:"7.4");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-20 08:37:08 +0200 (Mon, 20 Jun 2011)");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1145-1");
  script_cve_id("CVE-2011-1750", "CVE-2011-1751");
  script_name("Ubuntu Update for qemu-kvm USN-1145-1");

  script_description(desc);
  script_summary("Check for the Version of qemu-kvm");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.5+noroms-0ubuntu7.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.5+noroms-0ubuntu7.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.5+noroms-0ubuntu7.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras", ver:"0.12.3+noroms-0ubuntu9.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-kvm-extras-static", ver:"0.12.3+noroms-0ubuntu9.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.14.0+noroms-0ubuntu4.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
