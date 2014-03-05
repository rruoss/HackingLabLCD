###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openssl MDVSA-2012:006 (openssl)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in openssl:

  The DTLS implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f
  performs a MAC check only if certain padding is valid, which makes
  it easier for remote attackers to recover plaintext via a padding
  oracle attack (CVE-2011-4108).

  Double free vulnerability in OpenSSL 0.9.8 before 0.9.8s, when
  X509_V_FLAG_POLICY_CHECK is enabled, allows remote attackers to
  have an unspecified impact by triggering failure of a policy check
  (CVE-2011-4109).

  The SSL 3.0 implementation in OpenSSL before 0.9.8s and 1.x before
  1.0.0f does not properly initialize data structures for block cipher
  padding, which might allow remote attackers to obtain sensitive
  information by decrypting the padding data sent by an SSL peer
  (CVE-2011-4576).

  The Server Gated Cryptography (SGC) implementation in OpenSSL before
  0.9.8s and 1.x before 1.0.0f does not properly handle handshake
  restarts, which allows remote attackers to cause a denial of service
  via unspecified vectors (CVE-2011-4619).

  The updated packages have been patched to correct these issues.";

tag_affected = "openssl on Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:006");
  script_id(831527);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-20 11:08:57 +0530 (Fri, 20 Jan 2012)");
  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4619");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2012:006");
  script_name("Mandriva Update for openssl MDVSA-2012:006 (openssl)");

  script_description(desc);
  script_summary("Check for the Version of openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8h~3.12mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8s~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1.0.0-devel", rpm:"libopenssl1.0.0-devel~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl1.0.0-static-devel", rpm:"libopenssl1.0.0-static-devel~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8s~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl1.0.0-devel", rpm:"lib64openssl1.0.0-devel~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl1.0.0-static-devel", rpm:"lib64openssl1.0.0-static-devel~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.0a~1.9mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}