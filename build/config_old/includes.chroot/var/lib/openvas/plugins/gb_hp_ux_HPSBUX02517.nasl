###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for OpenSSL HPSBUX02517
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Remote unauthorized information disclosure
  unauthorized data modification
  Denial of Service (DoS)";
tag_affected = "OpenSSL on
  HP-UX B.11.11, B.11.23, B.11.31 running OpenSSL before vA.00.09.08n.";
tag_insight = "Potential security vulnerabilities has been identified with HP-UX OpenSSL. 
  These vulnerabilities could be exploited remotely for unauthorized 
  information disclosure, unauthorized data modification, and to create a 
  Denial of Service (DoS).";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02079216");
  script_id(835229);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-30 16:02:26 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "HPSBUX", value: "02517");
  script_cve_id("CVE-2009-3245", "CVE-2009-3555", "CVE-2009-4355", "CVE-2010-0433", "CVE-2010-0740");
  script_name("HP-UX Update for OpenSSL HPSBUX02517");

  script_description(desc);
  script_summary("Check for the Version of OpenSSL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:hp:hp-ux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.08n.003", rls:"HPUX11.31")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.08n.002", rls:"HPUX11.23")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CER", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-CONF", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-DOC", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-INC", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-LIB", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MAN", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-MIS", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PRNG", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-PVT", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-RUN", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"openssl.OPENSSL-SRC", revision:"A.00.09.08n.001", rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}