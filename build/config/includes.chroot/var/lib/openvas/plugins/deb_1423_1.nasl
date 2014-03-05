# OpenVAS Vulnerability Test
# $Id: deb_1423_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1423-1
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
tag_insight = "Several remote vulnerabilities have been discovered in sitebar, a
web based bookmark manager written in PHP.  The Common Vulnerabilities
Exposures project identifies the following problems:

CVE-2007-5491
A directory traversal vulnerability in the translation module allows
remote authenticated users to chmod arbitrary files to 0777 via ..
sequences in the lang parameter.

CVE-2007-5492
A static code injection vulnerability in the translation module allows
a remote authenticated user to execute arbitrary PHP code via the value
parameter.

CVE-2007-5693
An eval injection vulnerability in the translation module allows
remote authenticated users to execute arbitrary PHP code via the
edit parameter in an upd cmd action.

CVE-2007-5694
A path traversal vulnerability in the translation module allows
remote authenticated users to read arbitrary files via an absolute
path in the 'dir' parameter.

CVE-2007-5695
An error in command.php allows remote attackers to redirect users
to arbitrary web sites via the forward parameter in a Log In action.

CVE-2007-5692
Multiple cross site scripting flaws allow remote attackers to inject
arbitrary script or HTML fragments into several scripts.


For the stable distribution (etch), these problem have been fixed in version
3.3.8-7etch1.

For the old stable distribution (sarge), these problems have been fixed in
version 3.2.6-7.1sarge1

For the unstable distribution (sid), these problems have been fixed in version
3.3.8-12.1.

We recommend that you upgrade your sitebar package.";
tag_summary = "The remote host is missing an update to sitebar
announced via advisory DSA 1423-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201423-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(59958);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695", "CVE-2007-5692");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1423-1 (sitebar)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1423-1 (sitebar)");

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
if ((res = isdpkgvuln(pkg:"sitebar", ver:"3.2.6-7.1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sitebar", ver:"3.3.8-7etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
