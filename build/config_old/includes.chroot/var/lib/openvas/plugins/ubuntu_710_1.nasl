# OpenVAS Vulnerability Test
# $Id: ubuntu_710_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-710-1 (xine-lib)
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
  libxine-main1                   1.1.1+ubuntu2-7.10

Ubuntu 7.10:
  libxine1                        1.1.7-1ubuntu1.4

Ubuntu 8.04 LTS:
  libxine1                        1.1.11.1-1ubuntu3.2

Ubuntu 8.10:
  libxine1                        1.1.15-0ubuntu3.1

After a standard system upgrade you need to restart applications linked against
xine-lib, such as Totem-xine and Amarok, to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-710-1";

tag_summary = "The remote host is missing an update to xine-lib
announced via advisory USN-710-1.

For details on the issues addressed with this update, please
visit the referenced securtiy advisories.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63305);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5246", "CVE-2008-5248", "CVE-2008-5905", "CVE-2008-5906", "CVE-2008-2712", "CVE-2008-4101", "CVE-2005-2090", "CVE-2005-3510", "CVE-2006-3835", "CVE-2006-7195", "CVE-2006-7196", "CVE-2007-0450", "CVE-2007-1355", "CVE-2007-1358", "CVE-2007-1858", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2008-0128", "CVE-2008-3358", "CVE-2009-0042", "CVE-2009-0135", "CVE-2009-0136", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-710-1 (xine-lib)");


 script_description(desc);

 script_summary("Ubuntu USN-710-1 (xine-lib)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.1+ubuntu2-7.10", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine-main1", ver:"1.1.1+ubuntu2-7.10", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-doc", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-doc", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-all-plugins", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-bin", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-misc-plugins", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-x", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-doc", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-all-plugins", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-bin", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-misc-plugins", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1-x", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
