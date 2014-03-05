# OpenVAS Vulnerability Test
# $Id: ubuntu_738_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-738-1 (glib2.0)
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

Ubuntu 7.10:
  libglib2.0-0                    2.14.1-1ubuntu1.1
  libglib2.0-udeb                 2.14.1-1ubuntu1.1

Ubuntu 8.04 LTS:
  libglib2.0-0                    2.16.6-0ubuntu1.1
  libglib2.0-udeb                 2.16.6-0ubuntu1.1

Ubuntu 8.10:
  libglib2.0-0                    2.18.2-0ubuntu2.1
  libglib2.0-udeb                 2.18.2-0ubuntu2.1

After a standard system upgrade you need to reboot your computer to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-738-1";

tag_insight = "Diego Petten discovered that the Base64 encoding functions in GLib did not
properly handle large strings. If a user or automated system were tricked
into processing a crafted Base64 string, an attacker could possibly execute
arbitrary code with the privileges of the user invoking the program.";
tag_summary = "The remote host is missing an update to glib2.0
announced via advisory USN-738-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63619);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2008-4316");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Ubuntu USN-738-1 (glib2.0)");


 script_description(desc);

 script_summary("Ubuntu USN-738-1 (glib2.0)");

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
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgio-fam", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgio-fam", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
