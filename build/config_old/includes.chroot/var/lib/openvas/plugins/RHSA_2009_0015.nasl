# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0015.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:0015 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:0015.

The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment and
the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. These are
summarized in the Security Alerts from IBM.

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.6.0 SR3 Java release.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(63189);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5350", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5359", "CVE-2008-5360");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("RedHat Security Advisory RHSA-2009:0015");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:0015");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0015.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#critical");
 script_xref(name : "URL" , value : "http://www-128.ibm.com/developerworks/java/jdk/alerts/");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm", rpm:"java-1.6.0-ibm~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-demo", rpm:"java-1.6.0-ibm-demo~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-devel", rpm:"java-1.6.0-ibm-devel~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-javacomm", rpm:"java-1.6.0-ibm-javacomm~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-jdbc", rpm:"java-1.6.0-ibm-jdbc~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-plugin", rpm:"java-1.6.0-ibm-plugin~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-src", rpm:"java-1.6.0-ibm-src~1.6.0.3~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm", rpm:"java-1.6.0-ibm~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-accessibility", rpm:"java-1.6.0-ibm-accessibility~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-demo", rpm:"java-1.6.0-ibm-demo~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-devel", rpm:"java-1.6.0-ibm-devel~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-javacomm", rpm:"java-1.6.0-ibm-javacomm~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-jdbc", rpm:"java-1.6.0-ibm-jdbc~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-plugin", rpm:"java-1.6.0-ibm-plugin~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-src", rpm:"java-1.6.0-ibm-src~1.6.0.3~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
