###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-1681-1
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
tag_insight = "Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki Ishikawa, Bill
  Gianopoulos, Benoit Jacob, Gary Kwong, Robert O'Callahan, Jesse Ruderman,
  and Julian Seward discovered multiple memory safety issues affecting
  Firefox. If the user were tricked into opening a specially crafted page, an
  attacker could possibly exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2013-0769, CVE-2013-0749, CVE-2013-0770)

  Abhishek Arya discovered several user-after-free and buffer overflows in
  Firefox. An attacker could exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of the
  user invoking Firefox. (CVE-2013-0760, CVE-2013-0761, CVE-2013-0762,
  CVE-2013-0763, CVE-2013-0766, CVE-2013-0767, CVE-2013-0771, CVE-2012-5829)
  
  A stack buffer was discovered in Firefox. If the user were tricked into
  opening a specially crafted page, an attacker could possibly exploit this
  to cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2013-0768)
  
  Masato Kinugawa discovered that Firefox did not always properly display URL
  values in the address bar. A remote attacker could exploit this to conduct
  URL spoofing and phishing attacks. (CVE-2013-0759)
  
  Atte Kettunen discovered that Firefox did not properly handle HTML tables
  with a large number of columns and column groups. If the user were tricked
  into opening a specially crafted page, an attacker could exploit this to
  cause a denial of service via application crash, or potentially execute
  code with the privileges of the user invoking Firefox. (CVE-2013-0744)
  
  Jerry Baker discovered that Firefox did not always properly handle
  threading when performing downloads over SSL connections. An attacker could
  exploit this to cause a denial of service via application crash.
  (CVE-2013-0764)
  
  Olli Pettay and Boris Zbarsky discovered flaws in the Javacript engine of
  Firefox. An attacker could cause a denial of service via application crash,
  or potentially execute code with the privileges of the user invoking
  Firefox. (CVE-2013-0745, CVE-2013-0746)
  
  Jesse Ruderman discovered a flaw in the way Firefox handled plugins.  If a
  user were tricked into opening a specially crafted page, a remote attacker
  could exploit this to bypass security protections to conduct clickjacking
  attacks. (CVE-2013-0747)
  
  Jesse Ruderman discover ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "firefox on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-January/001948.html");
  script_id(841273);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:50:06 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2013-0769", "CVE-2013-0749", "CVE-2013-0770", "CVE-2013-0760",
                "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0766",
                "CVE-2013-0767", "CVE-2013-0771", "CVE-2012-5829", "CVE-2013-0768",
                "CVE-2013-0759", "CVE-2013-0744", "CVE-2013-0764", "CVE-2013-0745",
                "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0752", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0753",
                "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0743");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1681-1");
  script_name("Ubuntu Update for firefox USN-1681-1");

  script_description(desc);
  script_summary("Check for the Version of firefox");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"18.0+build1-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"18.0+build1-0ubuntu0.11.10.3", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"18.0+build1-0ubuntu0.10.04.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"18.0+build1-0ubuntu0.12.10.3", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}