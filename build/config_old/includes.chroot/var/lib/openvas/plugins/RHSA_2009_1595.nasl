# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1595.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:1595 ()
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
advisory RHSA-2009:1595.

The Common UNIX Printing System (CUPS) provides a portable printing layer
for UNIX operating systems.

A use-after-free flaw was found in the way CUPS handled references in its
file descriptors-handling interface. A remote attacker could, in a
specially-crafted way, query for the list of current print jobs for a
specific printer, leading to a denial of service (cupsd crash).
(CVE-2009-3553)

Several cross-site scripting (XSS) flaws were found in the way the CUPS web
server interface processed HTML form content. If a remote attacker could
trick a local user who is logged into the CUPS web interface into visiting
a specially-crafted HTML page, the attacker could retrieve and potentially
modify confidential CUPS administration data. (CVE-2009-2820)

Red Hat would like to thank Aaron Sigel of Apple Product Security for
responsibly reporting the CVE-2009-2820 issue.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
update, the cupsd daemon will be restarted automatically.";

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
 script_id(66287);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-2820", "CVE-2009-3553");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("RedHat Security Advisory RHSA-2009:1595");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:1595");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1595.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.7~11.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.3.7~11.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.7~11.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.3.7~11.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.3.7~11.el5_4.4", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
