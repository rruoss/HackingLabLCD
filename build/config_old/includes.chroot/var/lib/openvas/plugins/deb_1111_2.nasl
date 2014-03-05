# OpenVAS Vulnerability Test
# $Id: deb_1111_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1111-2
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
tag_insight = "It was discovered that a race condition in the process filesystem can lead
to privilege escalation.

The following matrix explains which kernel version for which architecture
fixes the problem mentioned above:

Debian 3.1 (sarge)
Source                      2.6.8-16sarge4
Alpha architecture          2.6.8-16sarge4
AMD64 architecture          2.6.8-12sarge4
Intel IA-32 architecture    2.6.8-16sarge4
Intel IA-64 architecture    2.6.8-14sarge4
PowerPC architecture        2.6.8-12sarge4
Sun Sparc architecture      2.6.8-15sarge4
IBM S/390                   2.6.8-5sarge4
Motorola 680x0              2.6.8-4sarge4
HP Precision                2.6.8-6sarge3
FAI                         1.9.1sarge3

The initial advisory lacked builds for the IBM S/390, Motorola 680x0 and HP
Precision architectures, which are now provided. Also, the kernels for the
FAI installer have been updated.

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to kernel-source-2.6.8 et. al.
announced via advisory DSA 1111-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201111-2";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57160);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-3625");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1111-2 (kernel-source-2.6.8 et. al.)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1111-2 (kernel-source-2.6.8 et. al.)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.6.8-s390", ver:"2.6.8-5sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3", ver:"2.6.8-5sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-generic", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-generic", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12-amd64-generic", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12-amd64-k8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12-amd64-k8-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12-em64t-p4", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-12-em64t-p4-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-12-amd64-generic", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-12-amd64-k8", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-12-amd64-k8-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-12-em64t-p4", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-12-em64t-p4-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-386", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-686", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-686-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-k7", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-k7-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-386", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-686", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-686-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-k7", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-k7-smp", ver:"2.6.8-16sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-itanium", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-itanium-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-mckinley", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-mckinley-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-itanium", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-itanium-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-mckinley", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-mckinley-smp", ver:"2.6.8-14sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-sparc32", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-sparc64", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-sparc64-smp", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-sparc32", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-sparc64", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-sparc64-smp", ver:"2.6.8-15sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-power3", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-power3-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-power4", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-power4-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-powerpc", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-3-powerpc-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-power3", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-power3-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-power4", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-power4-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-powerpc", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-powerpc-smp", ver:"2.6.8-12sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-32", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-32-smp", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-64", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-3-64-smp", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-32", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-32-smp", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-64", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-64-smp", ver:"2.6.8-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-s390", ver:"2.6.8-5sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-s390-tape", ver:"2.6.8-5sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-3-s390x", ver:"2.6.8-5sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-amiga", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-atari", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-bvme6000", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-hp", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mac", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme147", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme16x", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-q40", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-sun3", ver:"2.6.8-4sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
