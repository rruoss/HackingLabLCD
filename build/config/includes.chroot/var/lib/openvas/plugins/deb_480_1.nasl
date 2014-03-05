# OpenVAS Vulnerability Test
# $Id: deb_480_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 480-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.17 and 2.4.18 for the hppa
(PA-RISC) architecture.  The Common Vulnerabilities and Exposures
project identifies the following problems that will be fixed with this
update:

CVE-2004-0003

A vulnerability has been discovered in the R128 drive in the Linux
kernel which could potentially lead an attacker to gain
unauthorised privileges.  Alan Cox and Thomas Biege developed a
correction for this

CVE-2004-0010

Arjan van de Ven discovered a stack-based buffer overflow in the
ncp_lookup function for ncpfs in the Linux kernel, which could
lead an attacker to gain unauthorised privileges.  Petr Vandrovec
developed a correction for this.

CVE-2004-0109

zen-parse discovered a buffer overflow vulnerability in the
ISO9660 filesystem component of Linux kernel which could be abused
by an attacker to gain unauthorised root access.  Sebastian
Krahmer and Ernie Petrides developed a correction for this.

CVE-2004-0177

Solar Designer discovered an information leak in the ext3 code of
Linux.  In a worst case an attacker could read sensitive data such
as cryptographic keys which would otherwise never hit disk media.
Theodore Ts'o developed a correction for this.

CVE-2004-0178

Andreas Kies discovered a denial of service condition in the Sound
Blaster driver in Linux.  He also developed a correction for this.

These problems will also be fixed by upstream in Linux 2.4.26 and
future versions of 2.6.

For the stable distribution (woody) these problems have been fixed in
version 32.4 for Linux 2.4.17 and in version 62.3 for Linux 2.4.18.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your kernel packages immediately, either";
tag_summary = "The remote host is missing an update to kernel-image-2.4.17-hppa kernel-image-2.4.18-hppa
announced via advisory DSA 480-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20480-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53683);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 480-1 (kernel-image-2.4.17-hppa kernel-image-2.4.18-hppa)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 480-1 (kernel-image-2.4.17-hppa kernel-image-2.4.18-hppa)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.17-hppa", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.18-hppa", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-hppa", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32-smp", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64-smp", ver:"32.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-hppa", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-32", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-32-smp", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-64", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-64-smp", ver:"62.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}