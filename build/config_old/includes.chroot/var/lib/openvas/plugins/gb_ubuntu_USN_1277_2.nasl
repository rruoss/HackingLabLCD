###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mozvoikko USN-1277-2
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
tag_insight = "USN-1277-1 fixed vulnerabilities in Firefox. This update provides updated
  Mozvoikko and ubufox packages for use with Firefox 8.

  Original advisory details:
  Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
  invalid sequences in the Shift-JIS encoding. It may be possible to trigger
  this crash without the use of debugging APIs, which might allow malicious
  websites to exploit this vulnerability. An attacker could possibly use this
  flaw this to steal data or inject malicious scripts into web content.
  (CVE-2011-3648)

  Marc Schoenefeld discovered that using Firebug to profile a JavaScript file
  with many functions would cause Firefox to crash. An attacker might be able
  to exploit this without using the debugging APIs, which could potentially
  remotely crash the browser, resulting in a denial of service.
  (CVE-2011-3650)

  Jason Orendorff, Boris Zbarsky, Gregg Tavares, Mats Palmgren, Christian
  Holler, Jesse Ruderman, Simona Marcu, Bob Clary, and William McCloskey
  discovered multiple memory safety bugs in the browser engine used in
  Firefox and other Mozilla-based products. An attacker might be able to use
  these flaws to execute arbitrary code with the privileges of the user
  invoking Firefox or possibly crash the browser resulting in a denial of
  service. (CVE-2011-3651)

  It was discovered that Firefox could be caused to crash under certain
  conditions, due to an unchecked allocation failure, resulting in a denial
  of service. It might also be possible to execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2011-3652)

  Aki Helin discovered that Firefox does not properly handle links from SVG
  mpath elements to non-SVG elements. An attacker could use this
  vulnerability to crash Firefox, resulting in a denial of service, or
  possibly execute arbitrary code with the privileges of the user invoking
  Firefox. (CVE-2011-3654)

  It was discovered that an internal privilege check failed to respect the
  NoWaiverWrappers introduced with Firefox 4. An attacker could possibly use
  this to gain elevated privileges within the browser for web content.
  (CVE-2011-3655)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1277-2";
tag_affected = "mozvoikko on Ubuntu 11.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-November/001495.html");
  script_id(840815);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-25 12:00:50 +0530 (Fri, 25 Nov 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1277-2");
  script_cve_id("CVE-2011-3648", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3654", "CVE-2011-3655");
  script_name("Ubuntu Update for mozvoikko USN-1277-2");

  script_description(desc);
  script_summary("Check for the Version of mozvoikko");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu0.11.04.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.2-0ubuntu0.11.04.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
