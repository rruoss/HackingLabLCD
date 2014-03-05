# OpenVAS Vulnerability Test
# $Id: fcore_2009_11070.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-11070 (asterisk)
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

* Wed Nov  4 2009 Jeffrey C. Ollie  - 1.6.1.9-1 - Update to
1.6.1.9 to fix AST-2009-009/CVE-2008-7220 and AST-2009-008 - Fix obsoletes for
firmware subpackage

ChangeLog:

* Wed Nov  4 2009 Jeffrey C. Ollie  - 1.6.1.9-1
- Update to 1.6.1.9 to fix AST-2009-009/CVE-2008-7220 and AST-2009-008
- Fix obsoletes for firmware subpackage";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update asterisk' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11070";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory FEDORA-2009-11070.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66321);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
 script_cve_id("CVE-2008-7220");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 11 FEDORA-2009-11070 (asterisk)");


 script_description(desc);

 script_summary("Fedora Core 11 FEDORA-2009-11070 (asterisk)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=523277");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=533137");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"asterisk", rpm:"asterisk~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ais", rpm:"asterisk-ais~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-alsa", rpm:"asterisk-alsa~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-apidoc", rpm:"asterisk-apidoc~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-curl", rpm:"asterisk-curl~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-dahdi", rpm:"asterisk-dahdi~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-devel", rpm:"asterisk-devel~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-fax", rpm:"asterisk-fax~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-festival", rpm:"asterisk-festival~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ices", rpm:"asterisk-ices~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-jabber", rpm:"asterisk-jabber~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-jack", rpm:"asterisk-jack~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ldap", rpm:"asterisk-ldap~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-ldap-fds", rpm:"asterisk-ldap-fds~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-lua", rpm:"asterisk-lua~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-minivm", rpm:"asterisk-minivm~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-misdn", rpm:"asterisk-misdn~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-odbc", rpm:"asterisk-odbc~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-oss", rpm:"asterisk-oss~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-portaudio", rpm:"asterisk-portaudio~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-postgresql", rpm:"asterisk-postgresql~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-radius", rpm:"asterisk-radius~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-skinny", rpm:"asterisk-skinny~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-snmp", rpm:"asterisk-snmp~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-sqlite", rpm:"asterisk-sqlite~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-tds", rpm:"asterisk-tds~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-unistim", rpm:"asterisk-unistim~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-usbradio", rpm:"asterisk-usbradio~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail", rpm:"asterisk-voicemail~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-imap", rpm:"asterisk-voicemail-imap~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-odbc", rpm:"asterisk-voicemail-odbc~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-voicemail-plain", rpm:"asterisk-voicemail-plain~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"asterisk-debuginfo", rpm:"asterisk-debuginfo~1.6.1.9~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
