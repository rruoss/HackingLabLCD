###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for webkit USN-1617-1
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
tag_insight = "A large number of security issues were discovered in the WebKit browser and
  JavaScript engines. If a user were tricked into viewing a malicious
  website, a remote attacker could exploit a variety of issues related to web
  browser security, including cross-site scripting attacks, denial of
  service attacks, and arbitrary code execution.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1617-1";
tag_affected = "webkit on Ubuntu 12.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001878.html");
  script_id(841198);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-26 09:44:32 +0530 (Fri, 26 Oct 2012)");
  script_cve_id("CVE-2011-3031", "CVE-2011-3038", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3051", "CVE-2011-3053", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3064", "CVE-2011-3067", "CVE-2011-3076", "CVE-2011-3081", "CVE-2011-3086", "CVE-2011-3090", "CVE-2012-1521", "CVE-2012-3598", "CVE-2012-3601", "CVE-2012-3604", "CVE-2012-3611", "CVE-2012-3612", "CVE-2012-3617", "CVE-2012-3625", "CVE-2012-3626", "CVE-2012-3627", "CVE-2012-3628", "CVE-2012-3645", "CVE-2012-3652", "CVE-2012-3657", "CVE-2012-3669", "CVE-2012-3670", "CVE-2012-3671", "CVE-2012-3672", "CVE-2012-3674");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1617-1");
  script_name("Ubuntu Update for webkit USN-1617-1");

  script_description(desc);
  script_summary("Check for the Version of webkit");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
