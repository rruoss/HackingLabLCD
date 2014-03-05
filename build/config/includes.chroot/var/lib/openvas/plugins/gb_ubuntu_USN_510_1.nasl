###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-source-2.6.20 vulnerabilities USN-510-1
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
tag_insight = "A flaw was discovered in the PPP over Ethernet implementation.  Local
  attackers could manipulate ioctls and cause kernel memory consumption
  leading to a denial of service. (CVE-2007-2525)

  An integer underflow was discovered in the cpuset filesystem.  If mounted,
  local attackers could obtain kernel memory using large file offsets while
  reading the tasks file. This could disclose sensitive data. (CVE-2007-2875)
  
  Vilmos Nebehaj discovered that the SCTP netfilter code did not correctly
  validate certain states.  A remote attacker could send a specially crafted
  packet causing a denial of service. (CVE-2007-2876)
  
  Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
  systems.  A local attacker could corrupt a kernel_dirent struct and cause
  a denial of service. (CVE-2007-2878)
  
  A flaw in the sysfs_readdir function allowed a local user to cause a
  denial of service by dereferencing a NULL pointer. (CVE-2007-3104)
  
  A buffer overflow was discovered in the random number generator.  In
  environments with granular assignment of root privileges, a local attacker
  could gain additional privileges. (CVE-2007-3105)
  
  A flaw was discovered in the usblcd driver.  A local attacker could cause
  large amounts of kernel memory consumption, leading to a denial of service.
  (CVE-2007-3513)
  
  Zhongling Wen discovered that the h323 conntrack handler did not correctly
  handle certain bitfields.  A remote attacker could send a specially crafted
  packet and cause a denial of service. (CVE-2007-3642)
  
  A flaw was discovered in the CIFS mount security checking.  Remote
  attackers could spoof CIFS network traffic, which could lead a client
  to trust the connection. (CVE-2007-3843)
  
  It was discovered that certain setuid-root processes did not correctly
  reset process death signal handlers.  A local user could manipulate this
  to send signals to processes they would not normally have access to.
  (CVE-2007-3848)
  
  The Direct Rendering Manager for the i915 driver could be made to write
  to arbitrary memory locations.  An attacker with access to a running X11
  session could send a specially crafted buffer and gain root privileges.
  (CVE-2007-3851)
  
  It was discovered that the aacraid SCSI driver did not correctly check
  permissions on certain ioctls.  A local attacker could cause a denial
  of service or gain privileges. (CVE-2007-4308)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-510-1";
tag_affected = "linux-source-2.6.20 vulnerabilities on Ubuntu 7.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-August/000586.html");
  script_id(840139);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "510-1");
  script_cve_id("CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3104", "CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-3851", "CVE-2007-4308");
  script_name( "Ubuntu Update for linux-source-2.6.20 vulnerabilities USN-510-1");

  script_description(desc);
  script_summary("Check for the Version of linux-source-2.6.20 vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-386_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-generic_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-lowlatency_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server-bigiron_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-386_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-generic_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server-bigiron_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-386_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-generic_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server-bigiron_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-lowlatency_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-lowlatency_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.20_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.20_2.6.20-16.31", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
