# OpenVAS Vulnerability Test
# $Id: deb_1653_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1653-1 (linux-2.6)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-6716

Joe Jin reported a local denial of service vulnerability that
allows system users to trigger an oops due to an improperly
initialized data structure.

CVE-2008-1514

Jan Kratochvil reported a local denial of service vulnerability in
the ptrace interface for the s390 architecture. Local users can
trigger an invalid pointer dereference, leading to a system panic.

CVE-2008-3276

Eugene Teo reported an integer overflow in the DCCP subsystem that
may allow remote attackers to cause a denial of service in the
form of a kernel panic.

CVE-2008-3525

Eugene Teo reported a lack of capability checks in the kernel
driver for Granch SBNI12 leased line adapters (sbni), allowing
local users to perform privileged operations.

CVE-2008-3833

The S_ISUID/S_ISGID bits were not being cleared during an inode
splice, which, under certain conditions, can be exploited by local
users to obtain the privileges of a group for which they are not a
member. Mark Fasheh reported this issue.

CVE-2008-4210

David Watson reported an issue in the open()/creat() system calls
which, under certain conditions, can be exploited by local users
to obtain the privileges of a group for which they are not a
member.

CVE-2008-4302

A coding error in the splice subsystem allows local users to
attempt to unlock a page structure that has not been locked,
resulting in a system crash.

For the stable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-22etch3.

We recommend that you upgrade your linux-2.6, fai-kernels, and";
tag_summary = "The remote host is missing an update to linux-2.6
announced via advisory DSA 1653-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201653-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61775);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
 script_cve_id("CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1653-1 (linux-2.6)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1653-1 (linux-2.6)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.18-6", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-legacy", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-legacy", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-alpha", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-alpha", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-generic", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-generic", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-alpha", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.17+etch.22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-amd64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-rpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-iop32x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s3c2410", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-footbridge", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-arm", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-rpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-ixp4xx", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-ixp4xx", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-iop32x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-footbridge", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s3c2410", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc64-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc64-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-hppa", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-486", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-k7", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-k7", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-486", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-686-bigmem", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-k7", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"user-mode-linux", ver:"2.6.18-1um-2etch.22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-k7", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-686-bigmem", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-i386", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-itanium", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-itanium", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-mckinley", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-ia64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-mckinley", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-mips", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r4k-ip22", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r5k-ip32", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sb1-bcm91250a", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r4k-ip22", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-qemu", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-qemu", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sb1-bcm91250a", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r5k-ip32", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r4k-kn04", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r4k-kn04", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r3k-kn02", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r5k-cobalt", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-mipsel", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r5k-cobalt", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r3k-kn02", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-powerpc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-powerpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc-miboot", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-prep", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-prep", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc-miboot", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-powerpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-powerpc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-powerpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s390", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-s390x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s390x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-s390x", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390-tape", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-s390", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-sparc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc32", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-sparc", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-sparc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc32", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc64-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc64-smp", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc64", ver:"2.6.18.dfsg.1-22etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
