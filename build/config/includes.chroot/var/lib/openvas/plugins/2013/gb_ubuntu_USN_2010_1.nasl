###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-2010-1
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

if(description)
{
  script_id(841613);
  script_version("$Revision: 61 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-12 14:24:03 +0100 (Di, 12. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:57:15 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5593",
                "CVE-2013-5604", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597",
                "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602",
                "CVE-2013-5603");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ubuntu Update for thunderbird USN-2010-1");

  tag_insight = "Multiple memory safety issues were discovered in Thunderbird.
If a user were tricked in to opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute arbitrary code with
the privileges of the user invoking Thunderbird.(CVE-2013-1739, CVE-2013-5590,
CVE-2013-5591)

Jordi Chancel discovered that HTML select elements could display arbitrary
content. If a user had scripting enabled, an attacker could potentially
exploit this to conduct URL spoofing or clickjacking attacks.
(CVE-2013-5593)

Abhishek Arya discovered a crash when processing XSLT data in some
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-5604)

Dan Gohman discovered a flaw in the Javascript engine. If a user had
enabled scripting, when combined with other vulnerabilities an attacker
could possibly exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-5595)

Ezra Pool discovered a crash on extremely large pages. If a user had
scripting enabled, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-5596)

Byoungyoung Lee discovered a use-after-free when updating the offline
cache. If a user had scripting enabled, an attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5597)

Multiple use-after-free flaws were discovered in Thunderbird. If a user
had scripting enabled, an attacker could potentially exploit these to
cause a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2013-5599,
CVE-2013-5600, CVE-2013-5601)

A memory corruption flaw was discovered in the Javascript engine when
using workers with direct proxies. If a user had scripting enabled, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2013-5602)

Abhishek Arya discovered a use-after-free when interacting with HTML
document templates. If a user had scripting enabled, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5603)";

  tag_affected = "thunderbird on Ubuntu 13.10 ,
  Ubuntu 13.04 ,
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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "USN", value: "2010-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-October/002298.html");
  script_summary("Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.13", rls:"UBUNTU13.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.13", rls:"UBUNTU13.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
