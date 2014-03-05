# OpenVAS Vulnerability Test
# $Id: deb_218_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 218-1
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
tag_insight = "A cross site scripting vulnerability has been reported for Bugzilla, a
web-based bug tracking system.  Bugzilla does not properly sanitize
any input submitted by users.  As a result, it is possible for a
remote attacker to create a malicious link containing script code
which will be executed in the browser of a legitimate user, in the
context of the website running Bugzilla.  This issue may be exploited
to steal cookie-based authentication credentials from legitimate users
of the website running the vulnerable software.

This vulnerability only affects users who have the 'quips' feature
enabled and who upgraded from version 2.10 which did not exist inside
of Debian.  The Debian package history of Bugzilla starts with 1.13
and jumped to 2.13.  However, users could have installed version 2.10
prior to the Debian package.

For the current stable distribution (woody) this problem has been
fixed in version 2.14.2-0woody3.

The old stable distribution (potato) does not contain a Bugzilla
package.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your bugzilla packages.";
tag_summary = "The remote host is missing an update to bugzilla
announced via advisory DSA 218-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20218-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53740);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2002-2260");
 script_bugtraq_id(6257);
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 218-1 (bugzilla)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 218-1 (bugzilla)");

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
if ((res = isdpkgvuln(pkg:"bugzilla-doc", ver:"2.14.2-0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bugzilla", ver:"2.14.2-0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
