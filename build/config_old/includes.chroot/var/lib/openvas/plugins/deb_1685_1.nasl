# OpenVAS Vulnerability Test
# $Id: deb_1685_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1685-1 (uw-imap)
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
tag_insight = "Two vulnerabilities have been found in uw-imap, an IMAP
implementation. The Common Vulnerabilities and Exposures project
identifies the following problems:

It was discovered that several buffer overflows can be triggered via a
long folder extension argument to the tmail or dmail program. This
could lead to arbitrary code execution (CVE-2008-5005).

It was discovered that a NULL pointer dereference could be triggered by
a malicious response to the QUIT command leading to a denial of service
(CVE-2008-5006).

For the stable distribution (etch), these problems have been fixed in
version 2002edebian1-13.1+etch1.

For the unstable distribution (sid) and the testing distribution
(lenny), these problems have been fixed in version 2007d~dfsg-1.

We recommend that you upgrade your uw-imap packages.";
tag_summary = "The remote host is missing an update to uw-imap
announced via advisory DSA 1685-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201685-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(62955);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-12-23 18:28:16 +0100 (Tue, 23 Dec 2008)");
 script_cve_id("CVE-2008-5005", "CVE-2008-5006");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1685-1 (uw-imap)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1685-1 (uw-imap)");

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
if ((res = isdpkgvuln(pkg:"ipopd-ssl", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uw-imapd-ssl", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uw-mailutils", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc-client2002edebian", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipopd", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mlock", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uw-imapd", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libc-client-dev", ver:"2002edebian1-13.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
