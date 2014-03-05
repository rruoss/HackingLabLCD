###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux vulnerabilities USN-1090-1
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
tag_insight = "Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4076, CVE-2010-4077)

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (Ubuntu 10.10 was already fixed in a prior update.) (CVE-2010-4158)
  
  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163)
  
  Dan Rosenberg discovered that the RDS protocol did not correctly check
  ioctl arguments. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2010-4175)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1090-1";
tag_affected = "linux vulnerabilities on Ubuntu 10.04 LTS ,
  Ubuntu 10.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-March/001282.html");
  script_id(840615);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "1090-1");
  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4163", "CVE-2010-4175");
  script_name("Ubuntu Update for linux vulnerabilities USN-1090-1");

  script_description(desc);
  script_summary("Check for the Version of linux vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.35-28-generic-pae", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.35-28-generic", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.35-28-virtual", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-28-generic-pae", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-28-generic", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.35-28-virtual", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.35-1028.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-2.6.35-28", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.35-28", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-2.6.35", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-common", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"char-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"char-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-2.6.35-28-generic-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-2.6.35-28-generic-pae-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-2.6.35-28-virtual-di", ver:"2.6.35-28.49", rls:"UBUNTU10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-30-386", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-30-generic-pae", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-30-generic", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-30-386", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-30-generic-pae", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-30-generic", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-30-virtual", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-2.6.32-30", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-30", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-tools-common", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"char-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"char-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mouse-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"squashfs-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtio-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-2.6.32-30-generic-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vlan-modules-2.6.32-30-generic-pae-di", ver:"2.6.32-30.59", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
