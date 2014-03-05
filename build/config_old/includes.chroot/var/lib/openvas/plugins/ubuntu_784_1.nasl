# OpenVAS Vulnerability Test
# $Id: ubuntu_784_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-784-1 (imagemagick)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libmagick9                      6:6.2.4.5-0.6ubuntu0.9

Ubuntu 8.04 LTS:
  libmagick10                     7:6.3.7.9.dfsg1-2ubuntu1.1

Ubuntu 8.10:
  libmagick10                     7:6.3.7.9.dfsg1-2ubuntu3.1

Ubuntu 9.04:
  libmagickcore1                  7:6.4.5.4.dfsg1-1ubuntu3.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-784-1";

tag_insight = "It was discovered that ImageMagick did not properly verify the dimensions
of TIFF files. If a user or automated system were tricked into opening a
crafted TIFF file, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program.";
tag_summary = "The remote host is missing an update to imagemagick
announced via advisory USN-784-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64197);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-15 19:20:43 +0200 (Mon, 15 Jun 2009)");
 script_cve_id("CVE-2009-1882");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-784-1 (imagemagick)");


 script_description(desc);

 script_summary("Ubuntu USN-784-1 (imagemagick)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9c2a", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9-dev", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.2.4.5-0.6ubuntu0.9", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++10", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick10", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9-dev", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.3.7.9.dfsg1-2ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++10", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick10", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9-dev", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.3.7.9.dfsg1-2ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++1", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore1", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand1", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.4.5.4.dfsg1-1ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
