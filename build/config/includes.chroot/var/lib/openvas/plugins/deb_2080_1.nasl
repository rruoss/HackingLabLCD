# OpenVAS Vulnerability Test
# $Id: deb_2080_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2080-1 (ghostscript)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several security issues have been discovered in Ghostscript, the GPL
PostScript/PDF interpreter, which might lead to the execution of
arbitrary code if a user processes a malformed PDF or Postscript file.

For the stable distribution (lenny), these problems have been fixed in
version 8.62.dfsg.1-3.2lenny4.

For the unstable distribution (sid), these problems have been fixed in
version 8.71~dfsg-4.

We recommend that you upgrade your ghostscript packages.";
tag_summary = "The remote host is missing an update to ghostscript
announced via advisory DSA 2080-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202080-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67835);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2007-6725", "CVE-2008-3522", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0792", "CVE-2009-4270", "CVE-2010-1869");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 2080-1 (ghostscript)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2080-1 (ghostscript)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-common", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-dev", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs8", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
