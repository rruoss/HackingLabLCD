# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1127.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:1127 ()
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
advisory RHSA-2009:1127.

The kdelibs packages provide libraries for the K Desktop Environment (KDE).

A flaw was found in the way the KDE CSS parser handled content for the
CSS style attribute. A remote attacker could create a specially-crafted
CSS equipped HTML page, which once visited by an unsuspecting user, could
cause a denial of service (Konqueror crash) or, potentially, execute
arbitrary code with the privileges of the user running Konqueror.
(CVE-2009-1698)

A flaw was found in the way the KDE HTML parser handled content for the
HTML head element. A remote attacker could create a specially-crafted
HTML page, which once visited by an unsuspecting user, could cause a denial
of service (Konqueror crash) or, potentially, execute arbitrary code with
the privileges of the user running Konqueror. (CVE-2009-1690)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the KDE JavaScript garbage collector handled memory
allocation requests. A remote attacker could create a specially-crafted
HTML page, which once visited by an unsuspecting user, could cause a denial
of service (Konqueror crash) or, potentially, execute arbitrary code with
the privileges of the user running Konqueror. (CVE-2009-1687)

Users should upgrade to these updated packages, which contain backported
patches to correct these issues. The desktop must be restarted (log out,
then log back in) for this update to take effect.";

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
 script_id(64280);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("RedHat Security Advisory RHSA-2009:1127");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:1127");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1127.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#critical");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
