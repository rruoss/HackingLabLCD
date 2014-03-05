###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-1924-1
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
  script_id(841513);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:42:05 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705",
                "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711",
                "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for firefox USN-1924-1");

  tag_insight = "Jeff Gilbert, Henrik Skupin, Ben Turner, Christian Holler,
Andrew McCreight, Gary Kwong, Jan Varga and Jesse Ruderman discovered
multiple memory safety issues in Firefox. If the user were tricked in to
opening a specially crafted page, an attacker could possibly exploit these
to cause a denial of service via application crash, or potentially execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1701, CVE-2013-1702)

A use-after-free bug was discovered when the DOM is modified during a
SetBody mutation event. If the user were tricked in to opening a specially
crafted page, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1704)

A use-after-free bug was discovered when generating a CRMF request with
certain parameters. If the user were tricked in to opening a specially
crafted page, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1705)

Aki Helin discovered a crash when decoding a WAV file in some
circumstances. An attacker could potentially exploit this to cause a
denial of service. (CVE-2013-1708)

It was discovered that a document's URI could be set to the URI of
a different document. An attacker could potentially exploit this to
conduct cross-site scripting (XSS) attacks. (CVE-2013-1709)

A flaw was discovered when generating a CRMF request in certain
circumstances. An attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1710)

Bobby Holley discovered that XBL scopes could be used to circumvent
XrayWrappers in certain circumstances. An attacked could potentially
exploit this to conduct cross-site scripting (XSS) attacks or cause
undefined behaviour. (CVE-2013-1711)

Cody Crews discovered that some Javascript components performed security
checks against the wrong URI, potentially bypassing same-origin policy
restrictions. An attacker could exploit this to conduct cross-site
scripting (XSS) attacks or install addons from a malicious site.
(CVE-2013-1713)

Federico Lanusse discovered that web workers could bypass cross-origin
checks when using XMLHttpRequest. An attacker could potentially exploit
this to conduct cross-site scripting (XSS) attacks. (CVE-2013-1714)

Georgi Guninski and John Schoenick discovered that Java applets could
access local files under certain circumstances. An attacker could
potentially exploit this to steal confidential data. (CVE-2013-1717)";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "USN", value: "1924-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-August/002211.html");
  script_summary("Check for the Version of firefox");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"23.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"23.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"23.0+build2-0ubuntu0.13.04.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
