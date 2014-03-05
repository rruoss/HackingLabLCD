# OpenVAS Vulnerability Test
# $Id: deb_2342_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2342-1 (iceape)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been found in the Iceape internet suite, an
unbranded version of Seamonkey:

CVE-2011-3647

moz_bug_r_a4 discovered a privilege escalation vulnerability in
addon handling.

CVE-2011-3648

Yosuke Hasegawa discovered that incorrect handling of Shift-JIS
encodings could lead to cross-site scripting.

CVE-2011-3650

Marc Schoenefeld discovered that profiling the Javascript code
could lead to memory corruption.

The oldstable distribution (lenny) is not affected. The iceape package only
provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-9.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.14-9.

We recommend that you upgrade your iceape packages.";
tag_summary = "The remote host is missing an update to iceape
announced via advisory DSA 2342-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202342-1";

if(description)
{
 script_id(70557);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-11 02:29:15 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2342-1 (iceape)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Debian Security Advisory DSA 2342-1 (iceape)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"iceape", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceape-browser", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceape-dev", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"2.0.11-10", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}