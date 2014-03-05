# OpenVAS Vulnerability Test
# $Id: mdksa_2009_267.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:267 (xmlsec1)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "A vulnerability has been found and corrected in xmlsec1:

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1 prior to
1.2.12. An attacker could use this flaw to create a specially-crafted
XML file that forges an XML signature, allowing the attacker to
bypass authentication that is based on the XML Signature specification
(CVE-2009-0217).

This update fixes this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:267
http://www.kb.cert.org/vuls/id/466161";
tag_summary = "The remote host is missing an update to xmlsec1
announced via advisory MDVSA-2009:267.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66023);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
 script_cve_id("CVE-2009-0217");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandrake Security Advisory MDVSA-2009:267 (xmlsec1)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:267 (xmlsec1)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
