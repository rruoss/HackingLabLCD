# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0333.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:0333 ()
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
advisory RHSA-2009:0333.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A flaw was discovered in libpng that could result in libpng trying to
free() random memory if certain, unlikely error conditions occurred. If a
carefully-crafted PNG file was loaded by an application linked against
libpng, it could cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the application.
(CVE-2009-0040)

A flaw was discovered in the way libpng handled PNG images containing
unknown chunks. If an application linked against libpng attempted to
process a malformed, unknown chunk in a malicious PNG image, it could cause
the application to crash. (CVE-2008-1382)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications using libpng or libpng10 must be restarted for the update to
take effect.";

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
 script_id(63476);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2008-1382", "CVE-2009-0040");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("RedHat Security Advisory RHSA-2009:0333");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:0333");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0333.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.0.14~12", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.0.14~12", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.7~3.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.2.7~3.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.7~3.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng10", rpm:"libpng10~1.0.16~3.el4_7.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng10-debuginfo", rpm:"libpng10-debuginfo~1.0.16~3.el4_7.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng10-devel", rpm:"libpng10-devel~1.0.16~3.el4_7.3", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.10~7.1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.2.10~7.1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.10~7.1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
