###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for apt USN-1762-1
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
tag_insight = "Ansgar Burchardt discovered that APT incorrectly handled repositories that
  use InRelease files. The default Ubuntu repositories do not use InRelease
  files, so this issue only affected third-party repositories. If a remote
  attacker were able to perform a man-in-the-middle attack, this flaw could
  potentially be used to install altered packages.

  This update corrects the issue by disabling InRelease file support
  completely.";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "apt on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10";

  desc = "

    Vulnerability Insight:
    " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;



if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "insight" , value : tag_insight);
  }
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-March/002038.html");
  script_id(841358);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-15 10:05:22 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-1051");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1762-1");
  script_name("Ubuntu Update for apt USN-1762-1");

  script_description(desc);
  script_summary("Check for the Version of apt");
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

  if ((res = isdpkgvuln(pkg:"apt", ver:"0.8.16~exp12ubuntu10.10", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"apt", ver:"0.8.16~exp5ubuntu13.7", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"apt", ver:"0.9.7.5ubuntu5.4", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}