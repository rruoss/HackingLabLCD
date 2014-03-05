# OpenVAS Vulnerability Test
# $Id: fcore_2009_10165.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-10165 (kernel)
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

Update to kernel 2.6.27.35:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.31
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.32
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.33
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.34
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.35

ChangeLog:

* Sat Sep 26 2009 Chuck Ebbert   2.6.27.35-170.2.94
- Backport appletalk: Fix skb leak when ipddp interface is not loaded
(fixes CVE-2009-2903)
* Sat Sep 26 2009 Chuck Ebbert   2.6.27.35-170.2.93
- Backport KVM: x86: Disallow hypercalls for guest callers in rings > 0
(fixes CVE-2009-3290)
* Thu Sep 24 2009 Chuck Ebbert   2.6.27.35-170.2.92
- Linux 2.6.27.35
- Drop merged patches:
linux-2.6-nfsd-report-short-writes-fix.patch
linux-2.6-nfsd-report-short-writes.patch
* Tue Sep 15 2009 Chuck Ebbert   2.6.27.34-170.2.91
- Linux 2.6.27.34
- Drop merged patch: linux-2.6-slub-fix-destroy-by-rcu.patch
* Wed Sep  9 2009 Chuck Ebbert   2.6.27.32-170.2.90
- 2.6.27.32 final
- Drop linux-2.6-ocfs2-handle-len-0.patch, added after .32-rc1
* Mon Sep  7 2009 Chuck Ebbert   2.6.27.32-170.2.89.rc1
- Backport fix for b43 on ppc64 to 2.6.27 (#514787)
* Sun Sep  6 2009 Chuck Ebbert   2.6.27.32-170.2.88.rc1
- Add patches requested for the next stable release:
linux-2.6-slub-fix-destroy-by-rcu.patch (fixes bug in 2.6.27.29)
linux-2.6-ocfs2-handle-len-0.patch (fixes bug in 2.6.27.32-rc1)
* Fri Sep  4 2009 Chuck Ebbert   2.6.27.32-170.2.87.rc1
- Copy fix for NFS short write reporting from F-10 2.6.29 kernel (#493500)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update kernel' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10165";
tag_summary = "The remote host is missing an update to kernel
announced via advisory FEDORA-2009-10165.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64999);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2009-2903", "CVE-2009-3290", "CVE-2009-2847", "CVE-2009-2692", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-1895", "CVE-2009-1897", "CVE-2009-0065", "CVE-2008-5079", "CVE-2009-3001", "CVE-2009-3002");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-10165 (kernel)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-10165 (kernel)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=515392");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=524124");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=522331");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=519305");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug", rpm:"kernel-PAEdebug~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-devel", rpm:"kernel-PAEdebug-devel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAEdebug-debuginfo", rpm:"kernel-PAEdebug-debuginfo~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-bootwrapper", rpm:"kernel-bootwrapper~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-debuginfo", rpm:"kernel-smp-debuginfo~2.6.27.35~170.2.94.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
