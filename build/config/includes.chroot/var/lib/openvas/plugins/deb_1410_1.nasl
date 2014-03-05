# OpenVAS Vulnerability Test
# $Id: deb_1410_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1410-1
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
tag_insight = "Several vulnerabilities have been discovered in Ruby, an object-oriented
scripting language. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-5162

It was discovered that the Ruby HTTP(S) module performs insufficient
validation of SSL certificates, which may lead to man-in-the-middle
attacks.

CVE-2007-5770

It was discovered that the Ruby modules for FTP, Telnet, IMAP, POP
and SMTP perform insufficient validation of SSL certificates, which
may lead to man-in-the-middle attacks.

For the stable distribution (etch), these problems have been fixed in
version 1.8.5-4etch1. Packages for sparc will be provided later.

For the old stable distribution (sarge), these problems have been fixed
in version 1.8.2-7sarge6. Packages for sparc will be provided later.

We recommend that you upgrade your ruby1.8 packages.";
tag_summary = "The remote host is missing an update to ruby1.8
announced via advisory DSA 1410-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201410-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(59635);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-5162", "CVE-2007-5770");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1410-1 (ruby1.8)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1410-1 (ruby1.8)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.2-7sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irb1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-elisp", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rdoc1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.5-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
