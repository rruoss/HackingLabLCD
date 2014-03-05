# OpenVAS Vulnerability Test
# $Id: deb_1193_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1193-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 4.3.0.dfsg.1-14sarge2. This release lacks builds for the
Motorola 680x0 architecture, which failed due to diskspace constraints
on the build host. They will be released once this problem has been
resolved.

For the unstable distribution (sid) these problems have been fixed
in version 1:1.2.2-1 of libxfont and version 1:1.0.2-9 of xorg-server.

We recommend that you upgrade your XFree86 packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201193-1";
tag_summary = "The remote host is missing an update to xfree86
announced via advisory DSA 1193-1.

Several vulnerabilities have been discovered in the X Window System,
which may lead to the execution of arbitrary code or denial of service.
The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2006-3467

Chris Evan discovered an integer overflow in the code to handle
PCF fonts, which might lead to denial of service if a malformed
font is opened.

CVE-2006-3739

It was discovered that an integer overflow in the code to handle
Adobe Font Metrics might lead to the execution of arbitrary code.

CVE-2006-3740

It was discovered that an integer overflow in the code to handle
CMap and CIDFont font data might lead to the execution of arbitrary
code.

CVE-2006-4447

The XFree86 initialization code performs insufficient checking of
the return value of setuid() when dropping privileges, which might
lead to local privilege escalation.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(58696);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-3467", "CVE-2006-3739", "CVE-2006-3740", "CVE-2006-4447");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1193-1 (xfree86)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1193-1 (xfree86)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"pm-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"x-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"x-window-system", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-100dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-100dpi", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-75dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-75dpi", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-base-transcoded", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-base", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-cyrillic", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-scalable", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfree86-common", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa3-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-data", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-pic", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xspecs", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lbxproxy", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps1", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps1-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libice-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libice6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libice6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsm-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsm6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsm6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libx11-6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libx11-6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libx11-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxext-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxext6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxext6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxft1", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxft1-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxi-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxi6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxi6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmu-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmu6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmu6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmuu-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmuu1", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmuu1-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxp-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxp6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxp6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxpm-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxpm4", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxpm4-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxrandr-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxrandr2", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxrandr2-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxt-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxt6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxt6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtrap-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtrap6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtrap6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtst-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtst6", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxtst6-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxv-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxv1", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxv1-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proxymngr", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"twm", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"x-window-system-core", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"x-window-system-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xbase-clients", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdm", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfwp", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-dri", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-dri-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-gl", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-gl-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-gl-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-glu", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-glu-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-glu-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa3", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa4", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa4-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-static-dev", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-static-pic", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xmh", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-common", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfree86", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfree86-dbg", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xterm", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xutils", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"4.3.0.dfsg.1-14sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
