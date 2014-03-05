# OpenVAS Vulnerability Test
# $Id: fcore_2009_8802.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-8802 (qt)
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
tag_insight = "Update Information:

Qt's WebKit code did not properly handle numeric character
references, which could allow remote attackers to cause a
denial of service (memory corruption and application crash)
via a crafted HTML document.

Also included is:

* a fix for lib symlinks changing erroneously on upgrades
* a fix for Copy and paste issues
* added support for more x keycodes

ChangeLog:

* Tue Aug 18 2009 Than Ngo  - 4.5.2-2
- security fix for CVE-2009-1725
* Tue Aug 18 2009 Rex Dieter  4.5.2-1.2
- kde-qt: 287-qmenu-respect-minwidth
- kde-qt: 0288-more-x-keycodes (#475247)
* Wed Aug  5 2009 Rex Dieter  4.5.2-1.1
- use linker scripts for _debug targets (#510246)
- apply upstream patch to fix issue in Copy and paste
- optimize (icon-mostly) scriptlets
- -x11: Requires(post,postun): /sbin/ldconfig";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update qt' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8802";
tag_summary = "The remote host is missing an update to qt
announced via advisory FEDORA-2009-8802.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64717);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1725");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-8802 (qt)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-8802 (qt)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=513813");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-demos", rpm:"qt-demos~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-examples", rpm:"qt-examples~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-debuginfo", rpm:"qt-debuginfo~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"qt-doc", rpm:"qt-doc~4.5.2~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
