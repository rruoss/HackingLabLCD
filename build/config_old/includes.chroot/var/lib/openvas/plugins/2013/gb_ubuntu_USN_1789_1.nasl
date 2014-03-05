###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for postgresql-9.1 USN-1789-1
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
tag_insight = "Mitsumasa Kondo and Kyotaro Horiguchi discovered that PostgreSQL
  incorrectly handled certain connection requests containing database names
  starting with a dash. A remote attacker could use this flaw to damage or
  destroy files within a server's data directory. This issue only applied to
  Ubuntu 11.10, Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1899)

  Marko Kreen discovered that PostgreSQL incorrectly generated random
  numbers. An authenticated attacker could use this flaw to possibly guess
  another database user's random numbers. (CVE-2013-1900)

  Noah Misch discovered that PostgreSQL incorrectly handled certain privilege
  checks. An unprivileged attacker could use this flaw to possibly interfere
  with in-progress backups. This issue only applied to Ubuntu 11.10,
  Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1901)";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "postgresql-9.1 on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";

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
  script_id(841385);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-05 13:51:38 +0530 (Fri, 05 Apr 2013)");
  script_cve_id("CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ubuntu Update for postgresql-9.1 USN-1789-1");

  script_description(desc);
  script_xref(name: "USN", value: "1789-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-April/002068.html");
  script_summary("Check for the Version of postgresql-9.1");
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

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.04", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu11.10", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.17-0ubuntu10.04", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.23-0ubuntu8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.10", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
