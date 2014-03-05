# OpenVAS Vulnerability Test
# $Id: deb_1720_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1720-1 (typo3-src)
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
tag_insight = "Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework.

Marcus Krause and Michael Stucki from the TYPO3 security team
discovered that the jumpUrl mechanism discloses secret hashes enabling
a remote attacker to bypass access control by submitting the correct
value as a URL parameter and thus being able to read the content of
arbitrary files.

Jelmer de Hen and Dmitry Dulepov discovered multiple cross-site
scripting vulnerabilities in the backend user interface allowing
remote attackers to inject arbitrary web script or HTML.

As it is very likely that your encryption key has been exposed we
strongly recommend to change your encyption key via the install tool
after installing the update.

For the stable distribution (etch) these problems have been fixed in
version 4.0.2+debian-8.

For the testing distribution (lenny) these problems have been fixed in
version 4.2.5-1+lenny1.

For the unstable distribution (sid) these problems have been fixed in
version 4.2.6-1.

We recommend that you upgrade your typo3 package.";
tag_summary = "The remote host is missing an update to typo3-src
announced via advisory DSA 1720-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201720-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(63393);
 script_cve_id("CVE-2009-0815","CVE-2009-0816");
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1720-1 (typo3-src)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1720-1 (typo3-src)");

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
if ((res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-8", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-8", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
