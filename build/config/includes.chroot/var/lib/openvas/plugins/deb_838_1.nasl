# OpenVAS Vulnerability Test
# $Id: deb_838_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 838-1
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
tag_solution = "For the stable distribution (sarge), these problems have been fixed in
version 1.0.4-2sarge5

For the unstable distribution (sid), these problems have been fixed in
version 1.0.7-1

We recommend that you upgrade your mozilla-firefox package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20838-1";
tag_summary = "The remote host is missing an update to mozilla-firefox
announced via advisory DSA 838-1.

Multiple security vulnerabilities have been identified in the
mozilla-firefox web browser.  These vulnerabilities could allow an
attacker to execute code on the victim's machine via specially crafted
network resources.

CVE-2005-2701
Heap overrun in XBM image processing

CVE-2005-2702
Denial of service (crash) and possible execution of arbitrary
code via Unicode sequences with zero-width non-joiner
characters.

CVE-2005-2703
XMLHttpRequest header spoofing

CVE-2005-2704
Object spoofing using XBL <implements>

CVE-2005-2705
JavaScript integer overflow

CVE-2005-2706
Privilege escalation using about: scheme

CVE-2005-2707
Chrome window spoofing allowing windows to be created without
UI components such as a URL bar or status bar that could be
used to carry out phishing attacks";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(55515);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 838-1 (mozilla-firefox)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 838-1 (mozilla-firefox)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
