###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-1890-1
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
tag_insight = "Multiple memory safety issues were discovered in Firefox. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit these to cause a denial of service via application crash, or
  potentially execute arbitrary code with the privileges of the user invoking
  Firefox. (CVE-2013-1682, CVE-2013-1683)

  Abhishek Arya discovered multiple use-after-free bugs. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit these to execute arbitrary code with the privileges of the user
  invoking Firefox. (CVE-2013-1684, CVE-2013-1685, CVE-2013-1686)

  Mariusz Mlynski discovered that user defined code within the XBL scope of
  an element could be made to bypass System Only Wrappers (SOW). An attacker
  could potentially exploit this to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2013-1687)

  Mariusz Mlynski discovered that the profiler user interface incorrectly
  handled data from the profiler. If the user examined profiler output
  on a specially crafted page, an attacker could potentially exploit this to
  execute arbitrary code with the privileges of the user invoking Firefox.
  (CVE-2013-1688)

  A crash was discovered when reloading a page that contained content using
  the onreadystatechange event. An attacker could potentially exploit this
  to execute arbitrary code with the privileges of the user invoking Firefox
  (CVE-2013-1690)

  Johnathan Kuskos discovered that Firefox sent data in the body of
  XMLHttpRequest HEAD requests. An attacker could exploit this to conduct
  Cross-Site Request Forgery (CSRF) attacks. (CVE-2013-1692)

  Paul Stone discovered a timing flaw in the processing of SVG images with
  filters. An attacker could exploit this to view sensitive information.
  (CVE-2013-1693)

  Boris Zbarsky discovered a flaw in PreserveWrapper. An attacker could
  potentially exploit this to cause a denial of service via application
  crash, or execute code with the privileges of the user invoking Firefox.
  (CVE-2013-1694)

  Bob Owen discovered that a sandboxed iframe could use a frame element
  to bypass its own restrictions. (CVE-2013-1695)

  Frederic Buclin discovered that the X-Frame-Options header is ignored
  in multi-part responses. An attacker could potentially exploit this
  to conduct clickjacking attacks. (CVE-2013-1696)

  It was discovered that XrayWrappers could be bypassed to call
  content-defined methods in certain circumstances. An attacker could
  exploit this to cause undefined ...

  Description truncated, for more information please check the Reference URL";


tag_affected = "firefox on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS";
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
  script_id(841490);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-27 10:01:51 +0530 (Thu, 27 Jun 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685",
                "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690",
                "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695",
                "CVE-2013-1696", "CVE-2013-1697", "CVE-2013-1698", "CVE-2013-1699");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ubuntu Update for firefox USN-1890-1");

  script_description(desc);
  script_xref(name: "USN", value: "1890-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-June/002174.html");
  script_summary("Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.12.10", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.13.04", rls:"UBUNTU13.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
