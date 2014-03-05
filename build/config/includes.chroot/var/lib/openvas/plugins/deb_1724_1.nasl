# OpenVAS Vulnerability Test
# $Id: deb_1724_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1724-1 (moodle)
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
tag_insight = "Several vulnerabilities have been discovered in Moodle, an online
course management system.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-0500

It was discovered that the information stored in the log tables
was not properly sanitized, which could allow attackers to inject
arbitrary web code.

CVE-2009-0502

It was discovered that certain input via the Login as function
was not properly sanitised leading to the injection of arbitrary
web script.

CVE-2008-5153

Dmitry E. Oboukhov discovered that the SpellCheker plugin creates
temporary files insecurely, allowing a denial of service attack.
Since the plugin was unused, it is removed in this update.

For the stable distribution (etch) these problems have been fixed in
version 1.6.3-2+etch2.

For the testing (lenny) distribution these problems have been fixed in
version 1.8.2.dfsg-3+lenny1.

For the unstable (sid) distribution these problems have been fixed in
version 1.8.2.dfsg-4.

We recommend that you upgrade your moodle package.";
tag_summary = "The remote host is missing an update to moodle
announced via advisory DSA 1724-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201724-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(63410);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
 script_cve_id("CVE-2009-0500", "CVE-2009-0502", "CVE-2008-5153");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1724-1 (moodle)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1724-1 (moodle)");

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
if ((res = isdpkgvuln(pkg:"moodle", ver:"1.6.3-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
