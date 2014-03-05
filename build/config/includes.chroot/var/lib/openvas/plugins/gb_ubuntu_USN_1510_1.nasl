###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-1510-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian Smith,
  Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey discovered
  memory safety issues affecting Thunderbird. If the user were tricked into
  opening a specially crafted page, an attacker could possibly exploit these to
  cause a denial of service via application crash, or potentially execute code
  with the privileges of the user invoking Thunderbird. (CVE-2012-1948,
  CVE-2012-1949)

  Abhishek Arya discovered four memory safety issues affecting Thunderbird. If
  the user were tricked into opening a specially crafted page, an attacker could
  possibly exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Thunderbird.
  (CVE-2012-1951, CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

  Mariusz Mlynski discovered that the address bar may be incorrectly updated.
  Calls to history.forward and history.back could be used to navigate to a site
  while the address bar still displayed the previous site. A remote attacker
  could exploit this to conduct phishing attacks. (CVE-2012-1955)

  Mario Heiderich discovered that HTML &lt;embed&gt; tags were not filtered out of the
  HTML &lt;description&gt; of RSS feeds. A remote attacker could exploit this to
  conduct cross-site scripting (XSS) attacks via javascript execution in the HTML
  feed view. (CVE-2012-1957)

  Arthur Gerkis discovered a use-after-free vulnerability. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit this to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Thunderbird.
  (CVE-2012-1958)

  Bobby Holley discovered that same-compartment security wrappers (SCSW) could be
  bypassed to allow XBL access. If the user were tricked into opening a specially
  crafted page, an attacker could possibly exploit this to execute code with the
  privileges of the user invoking Thunderbird. (CVE-2012-1959)

  Tony Payne discovered an out-of-bounds memory read in Mozilla's color
  management library (QCMS). If the user were tricked into opening a specially
  crafted color profile, an attacker could possibly exploit this to cause a
  denial of service via application crash. (CVE-2012-1960)

  Fr&#233;d&#233;ric Buclin discovered that the X-Frame-Options header was ignored when its
  value was specified multiple times. An attacker could exploit this to conduct
  clickjacking attack ...

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1510-1";
tag_affected = "thunderbird on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-July/001763.html");
  script_id(841083);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-19 10:43:29 +0530 (Thu, 19 Jul 2012)");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952",
                "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957",
                "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961",
                "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1510-1");
  script_name("Ubuntu Update for thunderbird USN-1510-1");

  script_description(desc);
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}