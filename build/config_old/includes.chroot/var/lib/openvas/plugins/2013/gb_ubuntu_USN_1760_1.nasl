###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-backport-oneiric USN-1760-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "A failure to validate input was discovered in the Linux kernel's Xen
  netback (network backend) driver. A user in a guest OS may exploit this
  flaw to cause a denial of service to the guest OS and other guest domains.
  (CVE-2013-0216)

  A memory leak was discovered in the Linux kernel's Xen netback (network
  backend) driver. A user in a guest OS could trigger this flaw to cause a
  denial of service on the system. (CVE-2013-0217)
  
  Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
  Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
  guest OS user could exploit this flaw to cause a denial of service (crash
  the system) or gain guest OS privilege. (CVE-2013-0228)
  
  A flaw was reported in the permission checks done by the Linux kernel for
  /dev/cpu/*/msr. A local root user with all capabilities dropped could
  exploit this flaw to execute code with full root capabilities.
  (CVE-2013-0268)
  
  A flaw was discovered in the Linux kernel's vhost driver used to accelerate
  guest networking in KVM based virtual machines. A privileged guest user
  could exploit this flaw to crash the host system. (CVE-2013-0311)
  
  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)
  
  A flaw was discovered on the Linux kernel's VFAT filesystem driver when a
  disk is mounted with the utf8 option (this is the default on Ubuntu). On a
  system where disks/images can be auto-mounted or a FAT filesystem is
  mounted an unprivileged user can exploit the flaw to gain root privileges.
  (CVE-2013-1773)";


tag_affected = "linux-lts-backport-oneiric on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-March/002035.html");
  script_id(841359);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-15 10:05:24 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0228", "CVE-2013-0268",
               "CVE-2013-0311", "CVE-2013-0349", "CVE-2013-1773");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1760-1");
  script_name("Ubuntu Update for linux-lts-backport-oneiric USN-1760-1");

  script_description(desc);
  script_summary("Check for the Version of linux-lts-backport-oneiric");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic-pae", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-server", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.0.0-32-virtual", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
