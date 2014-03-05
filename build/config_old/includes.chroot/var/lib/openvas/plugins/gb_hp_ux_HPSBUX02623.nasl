###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Kerberos HPSBUX02623
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
tag_impact = "Remote unauthorized modification";
tag_affected = "Kerberos on
  HP-UX B.11.11 running the Kerberos Client software versions prior to 
  v1.3.5.11. HP-UX B.11.23 and B.11.31 running the Kerberos Client software 
  versions prior to v1.6.2.09.";
tag_insight = "Potential security vulnerabilities have been identified on HP-UX running 
  Kerberos. These vulnerabilities could be exploited remotely by an 
  unauthorized user to modify data, prompts, or responses.";
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
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02657328");
  script_id(835248);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:59:01 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "HPSBUX", value: "02623");
  script_cve_id("CVE-2010-1323", "CVE-2010-1324");
  script_name("HP-UX Update for Kerberos HPSBUX02623");

  script_description(desc);
  script_summary("Check for the Version of Kerberos");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA32SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA64SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-PRG", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-64SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-IA32SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-IA64SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-RUN", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-SHLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA32SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA64SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
