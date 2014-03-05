# OpenVAS Vulnerability Test
# $Id: fcore_2009_8582.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-8582 (libxml)
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
tag_insight = "This library allows old Gnome-1 applications to manipulate XML files.

Update Information:

This update includes patches from RHEL-3 addressing a number of security
vulnerabilities:

- CVE-2004-0110 (arbitrary code execution via a long URL)
- CVE-2004-0989 (arbitrary code execution via a long URL)
- CVE-2009-2414 (stack consumption DoS vulnerabilities)
- CVE-2009-2416 (use-after-free DoS vulnerabilities)

ChangeLog:

* Wed Aug 12 2009 Paul Howarth  1:1.8.17-24
- renumber existing patches to free up low-numbered patches for EL-3 patches
- add patch for CAN-2004-0110 and CAN-2004-0989 (#139090)
- add patch for CVE-2009-2414 and CVE-2009-2416 (#515195, #515205)
* Sat Jul 25 2009 Fedora Release Engineering  1:1.8.17-23
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild
* Mon Apr 20 2009 Paul Howarth  1:1.8.17-22
- rebuild for %{_isa} provides/requires";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update libxml' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8582";
tag_summary = "The remote host is missing an update to libxml
announced via advisory FEDORA-2009-8582.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64701);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2004-0110", "CVE-2004-0989", "CVE-2009-2414", "CVE-2009-2416", "CVE-2004-0110", "CVE-2004-0989");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 11 FEDORA-2009-8582 (libxml)");


 script_description(desc);

 script_summary("Fedora Core 11 FEDORA-2009-8582 (libxml)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=430644");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=430645");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=515195");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=515205");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxml", rpm:"libxml~1.8.17~24.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxml-devel", rpm:"libxml-devel~1.8.17~24.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxml-debuginfo", rpm:"libxml-debuginfo~1.8.17~24.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
