###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-source-2.6.15 vulnerability USN-489-1
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
tag_insight = "A flaw was discovered in dvb ULE decapsulation.  A remote attacker could
  send a specially crafted message and cause a denial of service.
  (CVE-2006-4623)

  The compat_sys_mount function allowed local users to cause a denial of
  service when mounting a smbfs filesystem in compatibility mode.
  (CVE-2006-7203)
  
  The Omnikey CardMan 4040 driver (cm4040_cs) did not limit the size of
  buffers passed to read() and write(). A local attacker could exploit
  this to execute arbitrary code with kernel privileges. (CVE-2007-0005)
  
  Due to an variable handling flaw in the  ipv6_getsockopt_sticky()
  function a local attacker could exploit the getsockopt() calls to read
  arbitrary kernel memory. This could disclose sensitive data.
  (CVE-2007-1000)
  
  Ilja van Sprundel discovered that Bluetooth setsockopt calls could
  leak kernel memory contents via an uninitialized stack buffer.  A local
  attacker could exploit this flaw to view sensitive kernel information.
  (CVE-2007-1353)
  
  A flaw was discovered in the handling of netlink messages.  Local
  attackers could cause infinite recursion leading to a denial of service.
  (CVE-2007-1861)
  
  The random number generator was hashing a subset of the available entropy,
  leading to slightly less random numbers. Additionally, systems without
  an entropy source would be seeded with the same inputs at boot time,
  leading to a repeatable series of random numbers. (CVE-2007-2453)
  
  A flaw was discovered in the PPP over Ethernet implementation.  Local
  attackers could manipulate ioctls and cause kernel memory consumption
  leading to a denial of service. (CVE-2007-2525)
  
  An integer underflow was discovered in the cpuset filesystem.  If mounted,
  local attackers could obtain kernel memory using large file offsets
  while reading the tasks file. This could disclose sensitive data.
  (CVE-2007-2875)
  
  Vilmos Nebehaj discovered that the SCTP netfilter code did not correctly
  validate certain states.  A remote attacker could send a specially
  crafted packet causing a denial of service. (CVE-2007-2876)
  
  Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
  systems.  A local attacker could corrupt a kernel_dirent struct and
  cause a denial of service. (CVE-2007-2878)
  
  A flaw was discovered in the cluster manager.  A remote attacker could
  connect to the DLM port and block further DLM operations.
  (CVE-2007-3380)
  
  A flaw was discovered in the usblcd driver.  A local attacker could
  cause large amounts of kernel memory consumption, leading to a denial
  of service. (CVE-2007-3513)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-489-1";
tag_affected = "linux-source-2.6.15 vulnerability on Ubuntu 6.06 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-July/000562.html");
  script_id(840028);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "489-1");
  script_cve_id("CVE-2006-4623", "CVE-2006-7203", "CVE-2007-0005", "CVE-2007-1000", "CVE-2007-1353", "CVE-2007-1861", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3380", "CVE-2007-3513");
  script_name( "Ubuntu Update for linux-source-2.6.15 vulnerability USN-489-1");

  script_description(desc);
  script_summary("Check for the Version of linux-source-2.6.15 vulnerability");
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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28-386_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28-686_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28-k7_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28-server-bigiron_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28-server_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-28_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-28-386_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-28-686_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-28-k7_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-28-server-bigiron_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-28-server_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.15_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.15_2.6.15-28.57", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
