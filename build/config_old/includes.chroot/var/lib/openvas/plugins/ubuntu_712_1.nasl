# OpenVAS Vulnerability Test
# $Id: ubuntu_712_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-712-1 (vim)
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
  vim                             1:6.4-006+2ubuntu6.2
  vim-runtime                     1:6.4-006+2ubuntu6.2

Ubuntu 7.10:
  vim                             1:7.1-056+2ubuntu2.1
  vim-runtime                     1:7.1-056+2ubuntu2.1

Ubuntu 8.04 LTS:
  vim                             1:7.1-138+1ubuntu3.1
  vim-runtime                     1:7.1-138+1ubuntu3.1

Ubuntu 8.10:
  vim                             1:7.1.314-3ubuntu3.1
  vim-runtime                     1:7.1.314-3ubuntu3.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-712-1";

tag_insight = "Jan Minar discovered that Vim did not properly sanitize inputs before invoking
the execute or system functions inside Vim scripts. If a user were tricked
into running Vim scripts with a specially crafted input, an attacker could
execute arbitrary code with the privileges of the user invoking the program.
(CVE-2008-2712)

Ben Schmidt discovered that Vim did not properly escape characters when
performing keyword or tag lookups. If a user were tricked into running specially
crafted commands, an attacker could execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4101)";
tag_summary = "The remote host is missing an update to vim
announced via advisory USN-712-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63307);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2008-2712", "CVE-2008-4101", "CVE-2005-2090", "CVE-2005-3510", "CVE-2006-3835", "CVE-2006-7195", "CVE-2006-7196", "CVE-2007-0450", "CVE-2007-1355", "CVE-2007-1358", "CVE-2007-1858", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2008-0128", "CVE-2008-3358", "CVE-2009-0042", "CVE-2009-0135", "CVE-2009-0136", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-712-1 (vim)");


 script_description(desc);

 script_summary("Ubuntu USN-712-1 (vim)");

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
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"6.4-006+2ubuntu6.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"7.1-056+2ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-nox", ver:"7.1-138+1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-dbg", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-nox", ver:"7.1.314-3ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source-files", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
