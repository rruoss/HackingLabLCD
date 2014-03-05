# OpenVAS Vulnerability Test
# $Id: fcore_2009_6166.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-6166 (webkitgtk)
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

WebKitGTK+ 1.1.8 contains many bug-fixes and updates including spell-checking
support, enhanced error reporting, lots of ATK enhancements, support for copying
images to the clipboard, and a new printing API (since 1.1.5) that allows
applications better control and monitoring of the printing process.    Also, a
potential buffer overflow  in SVGList::insertItemBefore has been fixed
(CVE-2009-0945); and the JIT compiler is now enabled by default for x86_64
systems.

Please see the upstream changelog for the full list of fixes and
enhancements:    http://svn.webkit.org/repository/webkit/trunk/WebKit/gtk/NEWS

ChangeLog:

* Fri May 29 2009 Peter Gordon  - 1.1.8-1
- Update to new upstream release (1.1.8)
* Thu May 28 2009 Peter Gordon  - 1.1.7-1
- Update to new upstream release (1.1.7)
- Remove jit build conditional. (JIT is now enabled by default on platforms
which support it: currently 32- and 64-bit x86.)
- Fix installation of the GtkLauncher demo program so that it
is a binary and not a script. (Fixes bug #443048.)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update webkitgtk' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6166";
tag_summary = "The remote host is missing an update to webkitgtk
announced via advisory FEDORA-2009-6166.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64396);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0945");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 11 FEDORA-2009-6166 (webkitgtk)");


 script_description(desc);

 script_summary("Fedora Core 11 FEDORA-2009-6166 (webkitgtk)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=502673");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=443048");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=484335");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~1.1.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"webkitgtk-devel", rpm:"webkitgtk-devel~1.1.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"webkitgtk-doc", rpm:"webkitgtk-doc~1.1.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"webkitgtk-debuginfo", rpm:"webkitgtk-debuginfo~1.1.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
