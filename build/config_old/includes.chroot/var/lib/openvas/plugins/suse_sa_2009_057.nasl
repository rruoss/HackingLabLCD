# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_057.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:057 (openssl)
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
tag_insight = "The TLS/SSLv3 protocol as implemented in openssl prior to this update
was not able to associate already sent data to a renegotiated connection.
This allowed man-in-the-middle attackers to inject HTTP requests in a
HTTPS session without being noticed.
For example Apache's mod_ssl was vulnerable to this kind of attack because
it uses openssl.

It is believed that this vulnerability is actively exploited in the wild to
get access to HTTPS protected web-sites.

Please note that renegotiation will be disabled for any application using
openssl by this update and may cause problems in some cases.
Additionally this attack is not limited to HTTP.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:057";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:057.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66302);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-3555");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("SuSE Security Advisory SUSE-SA:2009:057 (openssl)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:057 (openssl)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~149.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~149.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~149.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~119.7", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~119.7", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~119.7", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8h~28.2.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8h~25.2.13", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-64bit", rpm:"compat-openssl097g-debuginfo-64bit~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-64bit", rpm:"compat-openssl097g-64bit~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-64bit", rpm:"libopenssl0_9_8-64bit~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-64bit", rpm:"compat-openssl097g-64bit~0.9.7g~119.7", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-64bit", rpm:"libopenssl0_9_8-64bit~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-32bit", rpm:"compat-openssl097g-debuginfo-32bit~0.9.7g~149.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~149.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8k~3.5.3", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-32bit", rpm:"compat-openssl097g-debuginfo-32bit~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~146.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8h~28.11.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~119.7", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8g~47.10", rls:"openSUSE11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
