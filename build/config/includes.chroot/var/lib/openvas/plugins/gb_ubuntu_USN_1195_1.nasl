###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for webkit USN-1195-1
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
tag_insight = "A large number of security issues were discovered in the WebKit browser and
  JavaScript engines. If a user were tricked into viewing a malicious
  website, a remote attacker could exploit a variety of issues related to web
  browser security, including cross-site scripting attacks, denial of
  service attacks, and arbitrary code execution.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1195-1";
tag_affected = "webkit on Ubuntu 10.10 ,
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
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-August/001401.html");
  script_id(840730);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-27 16:37:49 +0200 (Sat, 27 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1195-1");
  script_cve_id("CVE-2010-1824", "CVE-2010-2646", "CVE-2010-2651", "CVE-2010-2900", "CVE-2010-2901", "CVE-2010-3120", "CVE-2010-3254", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-4040", "CVE-2010-4042", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4199", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
  script_name("Ubuntu Update for webkit USN-1195-1");

  script_description(desc);
  script_summary("Check for the Version of webkit");
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

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.7-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.7-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
