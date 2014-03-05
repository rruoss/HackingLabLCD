# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0420.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:0420 ()
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
advisory RHSA-2009:0420.

Ghostscript is a set of software that provides a PostScript interpreter, a
set of C procedures (the Ghostscript library, which implements the graphics
capabilities in the PostScript language) and an interpreter for Portable
Document Format (PDF) files.

It was discovered that the Red Hat Security Advisory RHSA-2009:0345 did not
address all possible integer overflow flaws in Ghostscript's International
Color Consortium Format library (icclib). Using specially-crafted ICC
profiles, an attacker could create a malicious PostScript or PDF file with
embedded images that could cause Ghostscript to crash or, potentially,
execute arbitrary code when opened. (CVE-2009-0792)

A missing boundary check was found in Ghostscript's CCITTFax decoding
filter. An attacker could create a specially-crafted PostScript or PDF file
that could cause Ghostscript to crash or, potentially, execute arbitrary
code when opened. (CVE-2007-6725)

Users of ghostscript are advised to upgrade to these updated packages,
which contain backported patches to correct these issues.";

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
 script_id(63764);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2007-6725", "CVE-2009-0792", "CVE-2009-0583");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("RedHat Security Advisory RHSA-2009:0420");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:0420");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0420.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.05~32.1.20", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~7.05~32.1.20", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~7.05~32.1.20", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~1.3~32.1.20", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.07~33.2.el4_7.8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~7.07~33.2.el4_7.8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~7.07~33.2.el4_7.8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~7.07~33.2.el4_7.8", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
