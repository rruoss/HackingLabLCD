###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-source-2.6.15/17/20 vulnerabilities USN-518-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Evan Teran discovered that the Linux kernel ptrace routines did not
  correctly handle certain requests robustly.  Local attackers could exploit
  this to crash the system, causing a denial of service.  (CVE-2007-3731)

  It was discovered that hugetlb kernels on PowerPC systems did not prevent
  the stack from colliding with reserved kernel memory.  Local attackers
  could exploit this and crash the system, causing a denial of service.
  (CVE-2007-3739)
  
  It was discovered that certain CIFS filesystem actions did not honor
  the umask of a process.  Local attackers could exploit this to gain
  additional privileges. (CVE-2007-3740)
  
  Wojciech Purczynski discovered that the Linux kernel ia32 syscall
  emulation in x86_64 kernels did not correctly clear the high bits of
  registers.  Local attackers could exploit this to gain root privileges.
  (CVE-2007-4573)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-518-1";
tag_affected = "linux-source-2.6.15/17/20 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-September/000595.html");
  script_id(840149);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "518-1");
  script_cve_id("CVE-2007-3731", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-4573");
  script_name( "Ubuntu Update for linux-source-2.6.15/17/20 vulnerabilities USN-518-1");

  script_description(desc);
  script_summary("Check for the Version of linux-source-2.6.15/17/20 vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-386_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-generic_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-lowlatency_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server-bigiron_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-386_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-generic_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server-bigiron_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-386_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-generic_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server-bigiron_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-lowlatency_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-lowlatency_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.20_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.20_2.6.20-16.32", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29-386_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29-686_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29-k7_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29-server-bigiron_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29-server_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-29_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-29-386_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-29-686_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-29-k7_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-29-server-bigiron_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-29-server_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.15_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.15_2.6.15-29.60", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-386_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-generic_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-386_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-generic_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-386_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-generic_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-kdump", ver:"2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.17_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.17_2.6.17.1-12.41", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
