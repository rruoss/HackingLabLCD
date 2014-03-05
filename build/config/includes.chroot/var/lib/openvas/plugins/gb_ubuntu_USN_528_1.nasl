###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mysql-dfsg-5.0 vulnerabilities USN-528-1
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
tag_insight = "Neil Kettle discovered that MySQL could be made to dereference a NULL
  pointer and divide by zero.  An authenticated user could exploit this
  with a crafted IF clause, leading to a denial of service. (CVE-2007-2583)

  Victoria Reznichenko discovered that MySQL did not always require the
  DROP privilege.  An authenticated user could exploit this via RENAME
  TABLE statements to rename arbitrary tables, possibly gaining additional
  database access. (CVE-2007-2691)
  
  It was discovered that MySQL could be made to overflow a signed char
  during authentication.  Remote attackers could use crafted authentication
  requests to cause a denial of service. (CVE-2007-3780)
  
  Phil Anderton discovered that MySQL did not properly verify access
  privileges when accessing external tables.  As a result, authenticated
  users could exploit this to obtain UPDATE privileges to external
  tables. (CVE-2007-3782)
  
  In certain situations, when installing or upgrading mysql, there was no
  notification that the mysql root user password needed to be set.  If the
  password was left unset, attackers would be able to obtain unrestricted
  access to mysql.  This is now checked during mysql start-up.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-528-1";
tag_affected = "mysql-dfsg-5.0 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-October/000605.html");
  script_id(840042);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "528-1");
  script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-3780", "CVE-2007-3782");
  script_name( "Ubuntu Update for mysql-dfsg-5.0 vulnerabilities USN-528-1");

  script_description(desc);
  script_summary("Check for the Version of mysql-dfsg-5.0 vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0_5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"4.1_5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0_5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.38-0ubuntu1.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0_5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0_5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.22-0ubuntu6.06.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0_5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0_5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.24a-9ubuntu2.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
