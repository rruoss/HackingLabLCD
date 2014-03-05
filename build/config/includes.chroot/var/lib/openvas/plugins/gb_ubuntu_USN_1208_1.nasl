###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-mvl-dove USN-1208-1
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

  Alex Shi and Eric Dumazet discovered that the network stack did not
  correctly handle packet backlogs. A remote attacker could exploit this by
  sending a large amount of network traffic to cause the system to run out of
  memory, leading to a denial of service. (CVE-2010-4251, CVE-2010-4805)
  
  It was discovered that the /proc filesystem did not correctly handle
  permission changes when programs executed. A local attacker could hold open
  files to examine details about programs running with higher privileges,
  potentially increasing the chances of exploiting additional
  vulnerabilities. (CVE-2011-1020)
  
  Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
  handle certain fields. If a system was running with Rose enabled, a remote
  attacker could send specially crafted traffic to gain root privileges.
  (CVE-2011-1493)
  
  Timo Warns discovered that the GUID partition parsing routines did not
  correctly validate certain structures. A local attacker with physical
  access could plug in a specially crafted block device to crash the system,
  leading to a denial of service. (CVE-2011-1577)
  
  Dan Rosenberg discovered that the IPv4 diagnostic routines did not
  correctly validate certain requests. A local attacker could exploit this to
  consume CPU resources, leading to a denial of service. (CVE-2011-2213)
  
  Vasiliy Kulikov discovered that taskstats listeners were not correctly
  handled. A local attacker could expoit this to exhaust memory and CPU
  resources, leading to a denial of service. (CVE-2011-2484)
  
  It was discovered that Bluetooth l2cap and rfcomm did not correctly
  initialize structures. A local attacker could exploit this to read portions
  of the kernel stack, leading to a loss of privacy. (CVE-2011-2492)
  
  Mauro Carvalho Chehab discovered that the si4713 radio driver did not
  correctly check the length of memory copies. If this hardware was
  available, a local attacker could exploit this to crash the system or gain
  root privileges. (CVE-2011-2700)
  
  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)
  
  The performance counter subsystem did not correctly handle certain
  counters. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2011-2918)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1208-1";
tag_affected = "linux-mvl-dove on Ubuntu 10.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-September/001418.html");
  script_id(840743);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1208-1");
  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2918");
  script_name("Ubuntu Update for linux-mvl-dove USN-1208-1");

  script_description(desc);
  script_summary("Check for the Version of linux-mvl-dove");
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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-418-dove", ver:"2.6.32-418.36", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
