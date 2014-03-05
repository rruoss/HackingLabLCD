###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ec2 USN-1161-1
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
tag_insight = "Vasiliy Kulikov discovered that kvm did not correctly clear memory. A local
  attacker could exploit this to read portions of the kernel stack, leading
  to a loss of privacy. (CVE-2010-3881)

  Timo Warns discovered that the LDM disk partition handling code did not
  correctly handle certain values. By inserting a specially crafted disk
  device, a local attacker could exploit this to gain root privileges.
  (CVE-2011-1017)
  
  Neil Horman discovered that NFSv4 did not correctly handle certain orders
  of operation with ACL data. A remote attacker with access to an NFSv4 mount
  could exploit this to crash the system, leading to a denial of service.
  (CVE-2011-1090)
  
  Timo Warns discovered that OSF partition parsing routines did not correctly
  clear memory. A local attacker with physical access could plug in a
  specially crafted block device to read kernel memory, leading to a loss of
  privacy. (CVE-2011-1163)
  
  Dan Rosenberg discovered that MPT devices did not correctly validate
  certain values in ioctl calls. If these drivers were loaded, a local
  attacker could exploit this to read arbitrary kernel memory, leading to a
  loss of privacy. (CVE-2011-1494, CVE-2011-1495)
  
  Tavis Ormandy discovered that the pidmap function did not correctly handle
  large requests. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2011-1593)
  
  Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
  not correctly validate certain socket structures. If this driver was
  loaded, a local attacker could crash the system, leading to a denial of
  service. (CVE-2011-1598, CVE-2011-1748)
  
  Vasiliy Kulikov discovered that the AGP driver did not check certain ioctl
  values. A local attacker with access to the video subsystem could exploit
  this to crash the system, leading to a denial of service, or possibly gain
  root privileges. (CVE-2011-1745, CVE-2011-2022)
  
  Vasiliy Kulikov discovered that the AGP driver did not check the size of
  certain memory allocations. A local attacker with access to the video
  subsystem could exploit this to run the system out of memory, leading to a
  denial of service. (CVE-2011-1746, CVE-2011-1747)
  
  Dan Rosenberg discovered that the DCCP stack did not correctly handle
  certain packet structures. A remote attacker could exploit this to crash
  the system, leading to a denial of service. (CVE-2011-1770)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1161-1";
tag_affected = "linux-ec2 on Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-July/001371.html");
  script_id(840698);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-18 15:23:56 +0200 (Mon, 18 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1161-1");
  script_cve_id("CVE-2010-3881", "CVE-2011-1017", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1770");
  script_name("Ubuntu Update for linux-ec2 USN-1161-1");

  script_description(desc);
  script_summary("Check for the Version of linux-ec2");
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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-317-ec2", ver:"2.6.32-317.36", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
