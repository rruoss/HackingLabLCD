###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mysql-5.1 USN-1397-1
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
tag_insight = "Multiple security issues were discovered in MySQL and this update includes
  new upstream MySQL versions to fix these issues.

  MySQL has been updated to 5.1.61 in Ubuntu 10.04 LTS, Ubuntu 10.10,
  Ubuntu 11.04 and Ubuntu 11.10. Ubuntu 8.04 LTS has been updated to
  MySQL 5.0.95.

  In addition to security fixes, the updated packages contain bug fixes, new
  features, and possibly incompatible changes.

  Please see the following for more information:
  http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html
  http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html
  http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1397-1";
tag_affected = "mysql-5.1 on Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-March/001627.html");
  script_id(840944);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-16 10:51:25 +0530 (Fri, 16 Mar 2012)");
  script_cve_id("CVE-2007-5925", "CVE-2008-3963", "CVE-2008-4098", "CVE-2008-4456",
                "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030",
                "CVE-2009-4484", "CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848",
                "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-2008", "CVE-2010-3677",
                "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681",
                "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834",
                "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838",
                "CVE-2010-3839", "CVE-2010-3840", "CVE-2011-2262", "CVE-2012-0075",
                "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112",
                "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1397-1");
  script_name("Ubuntu Update for mysql-5.1 USN-1397-1");

  script_description(desc);
  script_summary("Check for the Version of mysql-5.1");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0ubuntu0.11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.95-0ubuntu1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
