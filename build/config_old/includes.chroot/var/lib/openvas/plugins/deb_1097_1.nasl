# OpenVAS Vulnerability Test
# $Id: deb_1097_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1097-1
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
tag_insight = "The following matrix explains which kernel version for which architecture
fix the problems mentioned above:

Debian 3.1 (sarge)
Source                      2.4.27-10sarge3
Alpha architecture          2.4.27-10sarge3
ARM architecture            2.4.27-2sarge3
Intel IA-32 architecture    2.4.27-10sarge3
Intel IA-64 architecture    2.4.27-10sarge3
Motorola 680x0 architecture 2.4.27-3sarge3
Big endian MIPS             2.4.27-10.sarge3.040815-1
Little endian MIPS          2.4.27-10.sarge3.040815-1
PowerPC architecture        2.4.27-10sarge3
IBM S/390 architecture      2.4.27-2sarge3
Sun Sparc architecture      2.4.27-9sarge3

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 3.1 (sarge)
fai-kernels                 1.9.1sarge2
kernel-image-2.4.27-speakup 2.4.27-1.1sarge2
mindi-kernel                2.4.27-2sarge2
systemimager                3.2.3-6sarge2

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to kernel-source-2.4.27
announced via advisory DSA 1097-1. For information on issues
addressed in this update, please visit the referenced security
advisories.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201097-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56956);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-0038", "CVE-2006-0039", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-1368", "CVE-2006-1524", "CVE-2006-1525", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1097-1 (kernel-source-2.4.27)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1097-1 (kernel-source-2.4.27)");

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
if ((res = isdpkgvuln(pkg:"systemimager-client", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-i386-standard", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-common", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27-speakup", ver:"2.4.27-1.1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server-flamethrowerd", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-doc", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-ia64-standard", ver:"3.2.3-6sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-3", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscpc", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscstation", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-netwinder", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bast", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-lart", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-386", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k6", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-686", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-386", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-586tsc", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k6", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k7-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-386", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-586tsc", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-586tsc", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mindi-kernel", ver:"2.4.27-2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-speakup", ver:"2.4.27-1.1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-itanium-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-itanium", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme16x", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mac", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-amiga", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-q40", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme147", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-atari", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bvme6000", ver:"2.4.27-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-ip22", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-ip22", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-sb1-swarm-bn", ver:"2.4.27-10.sarge3.04081+5-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r3k-kn02", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-kn04", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-cobalt", ver:"2.4.27-10.sarge3.040815-+1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-lasat", ver:"2.4.27-10.sarge3.040815-1+", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-xxs1500", ver:"2.4.27-10.sarge3.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-powerpc", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-small", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-apus", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-apus", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-apus", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-smp", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-small", ver:"2.4.27-10sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390-tape", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390x", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32", ver:"2.4.27-9sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
