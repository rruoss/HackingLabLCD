###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for krb5 vulnerabilities USN-449-1
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
tag_insight = "The krb5 telnet service did not appropriately verify user names.  A
  remote attacker could log in as the root user by requesting a specially
  crafted user name. (CVE-2007-0956)

  The krb5 syslog library did not correctly verify the size of log
  messages.  A remote attacker could send a specially crafted message and
  execute arbitrary code with root privileges. (CVE-2007-0957)
  
  The krb5 administration service was vulnerable to a double-free in the
  GSS RPC library.  A remote attacker could send a specially crafted
  request and execute arbitrary code with root privileges. (CVE-2007-1216)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-449-1";
tag_affected = "krb5 vulnerabilities on Ubuntu 5.10 ,
  Ubuntu 6.06 LTS ,
  Ubuntu 6.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-April/000517.html");
  script_id(840098);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "449-1");
  script_cve_id("CVE-2007-0956", "CVE-2007-0957", "CVE-2007-1216");
  script_name( "Ubuntu Update for krb5 vulnerabilities USN-449-1");

  script_description(desc);
  script_summary("Check for the Version of krb5 vulnerabilities");
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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.4.3-5ubuntu0.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.4.3-9ubuntu1.2", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU5.10")
{

  if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.3.6-4ubuntu0.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
