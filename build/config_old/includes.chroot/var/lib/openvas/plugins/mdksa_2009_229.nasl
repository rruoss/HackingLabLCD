# OpenVAS Vulnerability Test
# $Id: mdksa_2009_229.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:229 (cyrus-imapd)
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
tag_insight = "A vulnerability has been found and corrected in cyrus-imapd:

Buffer overflow in the SIEVE script component (sieve/script.c) in
cyrus-imapd in Cyrus IMAP Server 2.2.13 and 2.3.14 allows local users
to execute arbitrary code and read or modify arbitrary messages via
a crafted SIEVE script, related to the incorrect use of the sizeof
operator for determining buffer length, combined with an integer
signedness error (CVE-2009-2632).

This update provides a solution to this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:229";
tag_summary = "The remote host is missing an update to cyrus-imapd
announced via advisory MDVSA-2009:229.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64838);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2009-2632");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandrake Security Advisory MDVSA-2009:229 (cyrus-imapd)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:229 (cyrus-imapd)");

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
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.3.11~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.3.12~0.p2.4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.3.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.1.16~5.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.1.16~5.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.1.16~5.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.1.16~5.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.1.16~5.5.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.2.13~2.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.3.12~0.p2.4.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
