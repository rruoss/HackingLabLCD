###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for postgresql vulnerabilities USN-568-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Nico Leidecker discovered that PostgreSQL did not properly
  restrict dblink functions. An authenticated user could exploit
  this flaw to access arbitrary accounts and execute arbitrary
  SQL queries. (CVE-2007-3278, CVE-2007-6601)

  It was discovered that the TCL regular expression parser used
  by PostgreSQL did not properly check its input. An attacker
  could send crafted regular expressions to PostgreSQL and cause
  a denial of service via resource exhaustion or database crash.
  (CVE-2007-4769, CVE-2007-4772, CVE-2007-6067)
  
  It was discovered that PostgreSQL executed VACUUM and ANALYZE
  operations within index functions with superuser privileges and
  also allowed SET ROLE and SET SESSION AUTHORIZATION within index
  functions. A remote authenticated user could exploit these flaws
  to gain privileges. (CVE-2007-6600)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-568-1";
tag_affected = "postgresql vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04 ,
  Ubuntu 7.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-January/000654.html");
  script_id(840326);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "568-1");
  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_name( "Ubuntu Update for postgresql vulnerabilities USN-568-1");

  script_description(desc);
  script_summary("Check for the Version of postgresql vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg5", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plperl", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plpython", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-pltcl", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-server-dev", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.2_8.2.6-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg5", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq4", ver:"8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plperl", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plpython", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-pltcl", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-server-dev", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.1_8.1.11-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg5", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq4", ver:"8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plperl", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plpython", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-pltcl", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-server-dev", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.1_8.1.11-0ubuntu0.6.10.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"libecpg-compat2", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libecpg5", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpgtypes2", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plperl", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-plpython", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-pltcl", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-server-dev", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.2_8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.2.6-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
