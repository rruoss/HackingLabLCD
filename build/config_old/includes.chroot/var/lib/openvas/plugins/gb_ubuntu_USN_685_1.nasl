###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for net-snmp vulnerabilities USN-685-1
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
tag_insight = "Wes Hardaker discovered that the SNMP service did not correctly validate
  HMAC authentication requests.  An unauthenticated remote attacker
  could send specially crafted SNMPv3 traffic with a valid username
  and gain access to the user's views without a valid authentication
  passphrase. (CVE-2008-0960)

  John Kortink discovered that the Net-SNMP Perl module did not correctly
  check the size of returned values.  If a user or automated system were
  tricked into querying a malicious SNMP server, the application using
  the Perl module could be made to crash, leading to a denial of service.
  This did not affect Ubuntu 8.10. (CVE-2008-2292)
  
  It was discovered that the SNMP service did not correctly handle large
  GETBULK requests.  If an unauthenticated remote attacker sent a specially
  crafted request, the SNMP service could be made to crash, leading to a
  denial of service. (CVE-2008-4309)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-685-1";
tag_affected = "net-snmp vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS ,
  Ubuntu 8.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-December/000796.html");
  script_id(840244);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "685-1");
  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
  script_name( "Ubuntu Update for net-snmp vulnerabilities USN-685-1");

  script_description(desc);
  script_summary("Check for the Version of net-snmp vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp9-dev", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp9", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmp", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmpd", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tkmib", ver:"5.2.1.2-4ubuntu2.3", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"libsnmp-dev", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp15", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmp", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmpd", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-python", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tkmib", ver:"5.4.1~dfsg-7.1ubuntu6.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libsnmp-dev", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp15", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmp", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmpd", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-python", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tkmib", ver:"5.4.1~dfsg-4ubuntu4.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"libsnmp-dev", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp10", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmp", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"snmpd", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tkmib", ver:"5.3.1-6ubuntu2.2", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
