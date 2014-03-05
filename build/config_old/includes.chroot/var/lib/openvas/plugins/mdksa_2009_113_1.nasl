# OpenVAS Vulnerability Test
# $Id: mdksa_2009_113_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:113-1 (cyrus-sasl)
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
tag_insight = "Multiple buffer overflows in the CMU Cyrus SASL library before 2.1.23
might allow remote attackers to execute arbitrary code or cause a
denial of service application crash) via strings that are used as
input to the sasl_encode64 function in lib/saslutil.c (CVE-2009-0688).

The updated packages have been patched to prevent this.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:113-1";
tag_summary = "The remote host is missing an update to cyrus-sasl
announced via advisory MDVSA-2009:113-1.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66369);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandriva Security Advisory MDVSA-2009:113-1 (cyrus-sasl)");


 script_description(desc);

 script_summary("Mandriva Security Advisory MDVSA-2009:113-1 (cyrus-sasl)");

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
if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~23.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
