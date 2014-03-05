# OpenVAS Vulnerability Test
# $Id: fcore_2009_2834.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-2834 (krb5)
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

This update incorporates patches to fix potential read overflow and NULL pointer
dereferences in the implementation of the SPNEGO GSSAPI mechanism
(CVE-2009-0844, CVE-2009-0845), attempts to free an uninitialized pointer during
protocol parsing (CVE-2009-0846), and a bug in length validation during protocol
parsing (CVE-2009-0847).

ChangeLog:

* Tue Apr  7 2009 Nalin Dahyabhai  1.6.3-16
- add patches for read overflow and null pointer dereference in the
implementation of the SPNEGO mechanism (CVE-2009-0844, CVE-2009-0845)
- add patch for attempt to free uninitialized pointer in libkrb5
(CVE-2009-0846)
- add patch to fix length validation bug in libkrb5 (CVE-2009-0847)
* Mon Apr  6 2009 Nalin Dahyabhai 
- pull in a couple of defuzzed patches from the F-10 version of this package,
dropping a redundant man page patch in the process";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update krb5' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2834";
tag_summary = "The remote host is missing an update to krb5
announced via advisory FEDORA-2009-2834.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63777);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 9 FEDORA-2009-2834 (krb5)");


 script_description(desc);

 script_summary("Fedora Core 9 FEDORA-2009-2834 (krb5)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=490634");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491033");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491036");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491034");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation-clients", rpm:"krb5-workstation-clients~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation-servers", rpm:"krb5-workstation-servers~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~16.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
