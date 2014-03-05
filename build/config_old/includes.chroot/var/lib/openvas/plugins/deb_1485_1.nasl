# OpenVAS Vulnerability Test
# $Id: deb_1485_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1485-1 (icedove)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Icedove mail
client, an unbranded version of the Thunderbird client. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0412

Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren and Paul
Nickerson discovered crashes in the layout engine, which might allow
the execution of arbitrary code.

CVE-2008-0413

Carsten Book, Wesley Garland, Igor Bukanov, moz_bug_r_a4, shutdown,
Philip Taylor and tgirmann discovered crashes in the Javascript
engine, which might allow the execution of arbitrary code.

CVE-2008-0415

moz_bug_r_a4 and Boris Zbarsky discovered discovered several
vulnerabilities in Javascript handling, which could allow
privilege escalation.

CVE-2008-0418

Gerry Eisenhaur and moz_bug_r_a4 discovered that a directory
traversal vulnerability in chrome: URI handling could lead to
information disclosure.

CVE-2008-0419

David Bloom discovered a race condition in the image handling of
designMode elements, which can lead to information disclosure or
potentially the execution of arbitrary code.

CVE-2008-0591

Michal Zalewski discovered that timers protecting security-sensitive
dialogs (which disable dialog elements until a timeout is reached)
could be bypassed by window focus changes through Javascript.

For the stable distribution (etch), these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1-0etch1.

The Mozilla products in the old stable distribution (sarge) are no
longer supported with security updates.

We recommend that you upgrade your icedove packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 1485-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201485-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60362);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1485-1 (icedove)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1485-1 (icedove)");

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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.13+1.5.0.15a.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.13+1.5.0.15b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
