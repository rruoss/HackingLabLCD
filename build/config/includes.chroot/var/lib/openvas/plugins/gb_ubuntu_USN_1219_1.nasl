###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-backport-maverick USN-1219-1
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
tag_insight = "Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
  packets. On some systems, a remote attacker could send specially crafted
  traffic to crash the system, leading to a denial of service.
  (CVE-2011-1576)

  Timo Warns discovered that the EFI GUID partition table was not correctly
  parsed. A physically local attacker that could insert mountable devices
  could exploit this to crash the system or possibly gain root privileges.
  (CVE-2011-1776)
  
  Vasiliy Kulikov and Dan Rosenberg discovered that ecryptfs did not
  correctly check the origin of mount points. A local attacker could exploit
  this to trick the system into unmounting arbitrary mount points, leading to
  a denial of service. (CVE-2011-1833)
  
  Dan Rosenberg discovered that the IPv4 diagnostic routines did not
  correctly validate certain requests. A local attacker could exploit this to
  consume CPU resources, leading to a denial of service. (CVE-2011-2213)
  
  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)
  
  Fernando Gont discovered that the IPv6 stack used predictable fragment
  identification numbers. A remote attacker could exploit this to exhaust
  network resources, leading to a denial of service. (CVE-2011-2699)
  
  Mauro Carvalho Chehab discovered that the si4713 radio driver did not
  correctly check the length of memory copies. If this hardware was
  available, a local attacker could exploit this to crash the system or gain
  root privileges. (CVE-2011-2700)
  
  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)
  
  The performance counter subsystem did not correctly handle certain
  counters. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2011-2918)
  
  Time Warns discovered that long symlinks were incorrectly handled on Be
  filesystems. A local attacker could exploit this with a malformed Be
  filesystem and crash the system, leading to a denial of service.
  (CVE-2011-2928)
  
  Darren Lavender discovered that the CIFS client incorrectly handled certain
  large values. A remote attacker with a malicious server could exploit this
  to crash the system or possibly execute arbitrary code as the root user.
  (CVE-2011-3191)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1219-1";
tag_affected = "linux-lts-backport-maverick on Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-September/001431.html");
  script_id(840762);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1219-1");
  script_cve_id("CVE-2011-1576", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2699", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-3191");
  script_name("Ubuntu Update for linux-lts-backport-maverick USN-1219-1");

  script_description(desc);
  script_summary("Check for the Version of linux-lts-backport-maverick");
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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.60~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.60~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.60~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.60~lucid1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
