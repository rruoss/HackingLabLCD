# OpenVAS Vulnerability Test
# $Id: deb_1916_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1916-1 (kdelibs)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Dan Kaminsky and Moxie Marlinspike discovered that kdelibs, core libraries from
the official KDE release, does not properly handle a '\0' character in a domain
name in the Subject Alternative Name field of an X.509 certificate, which allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted
certificate issued by a legitimate Certification Authority.


For the oldstable distribution (etch), this problem has been fixed in
version 4:3.5.5a.dfsg.1-8etch3

Due to a bug in the archive system, the fix for the stable distribution
(lenny), will be released as version 4:3.5.10.dfsg.1-0lenny3 once it is
available.

For the testing distribution (squeeze), and the unstable distribution (sid),
this problem has been fixed in version 4:3.5.10.dfsg.1-2.1


We recommend that you upgrade your kdelibs pakcages.";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory DSA 1916-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201916-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(66100);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-2702");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1916-1 (kdelibs)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1916-1 (kdelibs)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.5a.dfsg.1-8etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
