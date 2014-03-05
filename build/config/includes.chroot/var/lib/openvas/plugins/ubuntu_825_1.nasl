# OpenVAS Vulnerability Test
# $Id: ubuntu_825_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-825-1 (libvorbis)
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

Ubuntu 8.04 LTS:
  libvorbis0a                     1.2.0.dfsg-2ubuntu0.2

Ubuntu 8.10:
  libvorbis0a                     1.2.0.dfsg-3.1ubuntu0.8.10.1

Ubuntu 9.04:
  libvorbis0a                     1.2.0.dfsg-3.1ubuntu0.9.04.1

After a standard system upgrade you need to restart any applications that
use libvorbis, such as Totem and gtkpod, to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-825-1";

tag_insight = "It was discovered that libvorbis did not correctly handle certain malformed
ogg files. If a user were tricked into opening a specially crafted ogg file
with an application that uses libvorbis, an attacker could execute
arbitrary code with the user's privileges. (CVE-2009-2663)

USN-682-1 provided updated libvorbis packages to fix multiple security
vulnerabilities. The upstream security patch to fix CVE-2008-1420
introduced a regression when reading sound files encoded with libvorbis
1.0beta1. This update corrects the problem.

Original advisory details:

 It was discovered that libvorbis did not correctly handle certain
 malformed sound files. If a user were tricked into opening a specially
 crafted sound file with an application that uses libvorbis, an attacker
 could execute arbitrary code with the user's privileges. (CVE-2008-1420)";
tag_summary = "The remote host is missing an update to libvorbis
announced via advisory USN-825-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64781);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2008-1420", "CVE-2009-2663");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-825-1 (libvorbis)");


 script_description(desc);

 script_summary("Ubuntu USN-825-1 (libvorbis)");

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
if ((res = isdpkgvuln(pkg:"libvorbis-dev", ver:"1.2.0.dfsg-2ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis0a", ver:"1.2.0.dfsg-2ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisenc2", ver:"1.2.0.dfsg-2ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisfile3", ver:"1.2.0.dfsg-2ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis-dev", ver:"1.2.0.dfsg-3.1ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis0a", ver:"1.2.0.dfsg-3.1ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisenc2", ver:"1.2.0.dfsg-3.1ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisfile3", ver:"1.2.0.dfsg-3.1ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis-dev", ver:"1.2.0.dfsg-3.1ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbis0a", ver:"1.2.0.dfsg-3.1ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisenc2", ver:"1.2.0.dfsg-3.1ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libvorbisfile3", ver:"1.2.0.dfsg-3.1ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
