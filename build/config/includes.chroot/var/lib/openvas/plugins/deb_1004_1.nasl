# OpenVAS Vulnerability Test
# $Id: deb_1004_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1004-1
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.svn20050314-1sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 0.8.4.debian-2.

We recommend that you upgrade your vlc package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201004-1";
tag_summary = "The remote host is missing an update to vlc
announced via advisory DSA 1004-1.

Simon Kilvington discovered that specially crafted PNG images can trigger
a heap overflow in libavcodec, the multimedia library of ffmpeg, which may
lead to the execution of arbitrary code.
The vlc media player links statically against libavcodec.

The old stable distribution (woody) isn't affected by this problem.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56412);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(15743);
 script_cve_id("CVE-2005-4048");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1004-1 (vlc)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1004-1 (vlc)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"gnome-vlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gvlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kvlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qvlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-alsa", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-esd", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-ggi", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-gnome", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-gtk", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-qt", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-sdl", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-glide", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.1.svn20050314-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
