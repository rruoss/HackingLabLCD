# OpenVAS Vulnerability Test
# $Id: ubuntu_829_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-829-1 (qt4-x11)
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
  libqt4-core                     4.3.4-0ubuntu3.1

Ubuntu 8.10:
  libqt4-network                  4.4.3-0ubuntu1.3

Ubuntu 9.04:
  libqt4-network                  4.5.0-0ubuntu4.2

After a standard system upgrade you need to restart your session to effect
the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-829-1";

tag_insight = "It was discovered that Qt did not properly handle certificates with NULL
characters in the Subject Alternative Name field of X.509 certificates. An
attacker could exploit this to perform a man in the middle attack to view
sensitive information or alter encrypted communications. (CVE-2009-2700)";
tag_summary = "The remote host is missing an update to qt4-x11
announced via advisory USN-829-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64890);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2009-2700");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-829-1 (qt4-x11)");


 script_description(desc);

 script_summary("Ubuntu USN-829-1 (qt4-x11)");

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
if ((res = isdpkgvuln(pkg:"qt4-doc", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-debug", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dev", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-gui", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-designer", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4.3.4-0ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-doc", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-designer", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dev", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-gui", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-help", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-script", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-svg", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-test", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xml", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqtcore4", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqtgui4", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-demos", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-designer", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4.4.3-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-doc", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-core", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-designer", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dev-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-dev", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-gui", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-help", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-script", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-scripttools", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-sql", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-svg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-test", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xml", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqtcore4", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libqtgui4", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-demos-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-demos", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-designer", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-dev-tools-dbg", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-qmake", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4.5.0-0ubuntu4.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
