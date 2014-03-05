# OpenVAS Vulnerability Test
# $Id: mdksa_2009_216.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:216 (mozilla-thunderbird)
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
tag_insight = "A number of security vulnerabilities have been discovered in the NSS
and NSPR libraries and in Mozilla Thunderbird:

Security issues in nss prior to 3.12.3 could lead to a
man-in-the-middle attack via a spoofed X.509 certificate
(CVE-2009-2408) and md2 algorithm flaws (CVE-2009-2409), and also
cause a denial-of-service and possible code execution via a long
domain name in X.509 certificate (CVE-2009-2404).

A vulnerability was found in xmltok_impl.c (expat) that with
specially crafted XML could be exploited and lead to a denial of
service attack. Related to CVE-2009-2625.

This update provides the latest versions of the NSS and NSPR libraries
and Thunderbird which are not vulnerable to these issues.

Affected: Corporate 3.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:216
http://www.mozilla.org/security/announce/2009/mfsa2009-42.html";
tag_summary = "The remote host is missing an update to mozilla-thunderbird
announced via advisory MDVSA-2009:216.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64688);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-2408", "CVE-2009-2409", "CVE-2009-2404", "CVE-2009-2625");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Mandrake Security Advisory MDVSA-2009:216 (mozilla-thunderbird)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:216 (mozilla-thunderbird)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"libnspr4", rpm:"libnspr4~4.7.5~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnspr-devel", rpm:"libnspr-devel~4.7.5~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnss3", rpm:"libnss3~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnss-devel", rpm:"libnss-devel~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnss-static-devel", rpm:"libnss-static-devel~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsqlite3_0", rpm:"libsqlite3_0~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsqlite3-devel", rpm:"libsqlite3-devel~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsqlite3-static-devel", rpm:"libsqlite3-static-devel~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-devel", rpm:"mozilla-thunderbird-devel~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gu_IN", rpm:"mozilla-thunderbird-gu_IN~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-mk", rpm:"mozilla-thunderbird-mk~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~2.0.0.23~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"sqlite3-tools", rpm:"sqlite3-tools~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64nspr4", rpm:"lib64nspr4~4.7.5~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64nspr-devel", rpm:"lib64nspr-devel~4.7.5~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64nss3", rpm:"lib64nss3~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64nss-devel", rpm:"lib64nss-devel~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64nss-static-devel", rpm:"lib64nss-static-devel~3.12.3.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sqlite3_0", rpm:"lib64sqlite3_0~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sqlite3-devel", rpm:"lib64sqlite3-devel~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64sqlite3-static-devel", rpm:"lib64sqlite3-static-devel~3.6.15~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
