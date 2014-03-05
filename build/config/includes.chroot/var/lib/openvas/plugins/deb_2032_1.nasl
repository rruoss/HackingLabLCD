# OpenVAS Vulnerability Test
# $Id: deb_2032_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2032-1 (libpng)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2009-2042

libpng does not properly parse 1-bit interlaced images with width values
that are not divisible by 8, which causes libpng to include
uninitialized bits in certain rows of a PNG file and might allow remote
attackers to read portions of sensitive memory via out-of-bounds
pixels in the file.

CVE-2010-0205

libpng does not properly handle compressed ancillary-chunk data that has
a disproportionately large uncompressed representation, which allows
remote attackers to cause a denial of service (memory and CPU
consumption, and  application hang) via a crafted PNG file

For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny3.

For the testing (squeeze) and unstable (sid) distribution, these
problems have been fixed in version 1.2.43-1

We recommend that you upgrade your libpng package.";
tag_summary = "The remote host is missing an update to libpng
announced via advisory DSA 2032-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202032-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67267);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2009-2042", "CVE-2010-0205");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2032-1 (libpng)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2032-1 (libpng)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.27-2+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.27-2+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.27-2+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
