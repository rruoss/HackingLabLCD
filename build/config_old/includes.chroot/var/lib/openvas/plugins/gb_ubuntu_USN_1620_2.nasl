###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-1620-2
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
tag_insight = "USN-1620-1 fixed vulnerabilities in Firefox. This update provides the
  corresponding updates for Thunderbird. Please note that Thunderbird is only
  affected by window.location issues through RSS feeds and extensions that
  load web content.

  Original advisory details:
  
  Mariusz Mlynski and others discovered several flaws in Firefox that allowed
  a remote attacker to conduct cross-site scripting (XSS) attacks.
  (CVE-2012-4194, CVE-2012-4195)
  
  Antoine Delignat-Lavaud discovered a flaw in the way Firefox handled the
  Location object. If a user were tricked into opening a specially crafted
  page, a remote attacker could exploit this to bypass security protections
  and perform cross-origin reading of the Location object. (CVE-2012-4196)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1620-2";
tag_affected = "thunderbird on Ubuntu 12.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001883.html");
  script_id(841204);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-31 17:31:41 +0530 (Wed, 31 Oct 2012)");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1620-2");
  script_name("Ubuntu Update for thunderbird USN-1620-2");

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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"16.0.2+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
