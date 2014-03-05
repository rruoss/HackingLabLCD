# OpenVAS Vulnerability Test
# $Id: deb_439_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 439-1
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
tag_insight = "Several local root exploits have been discovered recently in the Linux
kernel.  This security advisory updates the PowerPC/Apus kernel for
Debian GNU/Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:

CVE-2003-0961:

An integer overflow in brk() system call (do_brk() function) for
Linux allows a local attacker to gain root privileges.  Fixed
upstream in Linux 2.4.23.

CVE-2003-0985:

Paul Starzetz discovered a flaw in bounds checking in mremap() in
the Linux kernel (present in version 2.4.x and 2.6.x) which may
allow a local attacker to gain root privileges.  Version 2.2 is not
affected by this bug.  Fixed upstream in Linux 2.4.24.

CVE-2004-0077:

Paul Starzetz and Wojciech Purczynski of isec.pl discovered a
critical security vulnerability in the memory management code of
Linux inside the mremap(2) system call.  Due to missing function
return value check of internal functions a local attacker can gain
root privileges.  Fixed upstream in Linux 2.4.25 and 2.6.3.

For the stable distribution (woody) this problem has been fixed in
version 2.4.26/20040204 of lart, netwinder and riscpc image and in
version 20040204 of kernel-patch-2.4.16-arm.

Other architectures will probably mentioned in a separate advisory or
are not affected (m68k).

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your Linux kernel packages immediately.";
tag_summary = "The remote host is missing an update to kernel-image-2.4.16-lart, kernel-image-2.4.16-netwinder,  kernel-image-2.4.16-riscpc, kernel-patch-2.4.16-arm
announced via advisory DSA 439-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20439-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53140);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 439-1 (kernel)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 439-1 (kernel)");

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
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.16-arm", ver:"20040204", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.16-lart", ver:"20040204", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.16", ver:"20040204", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.16-netwinder", ver:"20040204", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.16-riscpc", ver:"20040204", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
