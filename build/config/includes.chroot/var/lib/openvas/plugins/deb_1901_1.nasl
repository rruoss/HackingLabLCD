# OpenVAS Vulnerability Test
# $Id: deb_1901_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1901-1 (mediawiki1.7)
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
tag_insight = "Several vulnerabilities have been discovered in mediawiki1.7, a website engine
for collaborative work. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-5249

David Remahl discovered that mediawiki1.7 is prone to a cross-site scripting attack.

CVE-2008-5250

David Remahl discovered that mediawiki1.7, when Internet Explorer is used and
uploads are enabled, or an SVG scripting browser is used and SVG uploads are
enabled, allows remote authenticated users to inject arbitrary web script or
HTML by editing a wiki page.

CVE-2008-5252

David Remahl discovered that mediawiki1.7 is prone to a cross-site request
forgery vulnerability in the Special:Import feature.

CVE-2009-0737

It was discovered that mediawiki1.7 is prone to a cross-site scripting attack in
the web-based installer.


For the oldstable distribution (etch), these problems have been fixed in version
1.7.1-9etch1 for mediawiki1.7, and mediawiki is not affected (it is a
metapackage for mediawiki1.7).

The stable (lenny) distribution does not include mediawiki1.7, and these
problems have been fixed in version 1:1.12.0-2lenny3 for mediawiki which was
already included in the lenny release.

The unstable (sid) and testing (squeeze) distributions do not
include mediawiki1.7, and these problems have been fixed in version 1:1.14.0-1
for mediawiki.


We recommend that you upgrade your mediawiki1.7 packages.";
tag_summary = "The remote host is missing an update to mediawiki1.7
announced via advisory DSA 1901-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201901-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(65007);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2009-0737");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1901-1 (mediawiki1.7)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1901-1 (mediawiki1.7)");

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
if ((res = isdpkgvuln(pkg:"mediawiki1.7", ver:"1.7.1-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mediawiki1.7-math", ver:"1.7.1-9etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
