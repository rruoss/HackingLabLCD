# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1529.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:1529 ()
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
advisory RHSA-2009:1529.

Samba is a suite of programs used by machines to share files, printers, and
other information.

A denial of service flaw was found in the Samba smbd daemon. An
authenticated, remote user could send a specially-crafted response that
would cause an smbd child process to enter an infinite loop. An
authenticated, remote user could use this flaw to exhaust system resources
by opening multiple CIFS sessions. (CVE-2009-2906)

An uninitialized data access flaw was discovered in the smbd daemon when
using the non-default dos filemode configuration option in smb.conf. An
authenticated, remote user with write access to a file could possibly use
this flaw to change an access control list for that file, even when such
access should have been denied. (CVE-2009-1888)

A flaw was discovered in the way Samba handled users without a home
directory set in the back-end password database (e.g. /etc/passwd). If a
share for the home directory of such a user was created (e.g. using the
automated [homes] share), any user able to access that share could see
the whole file system, possibly bypassing intended access restrictions.
(CVE-2009-2813)

The mount.cifs program printed CIFS passwords as part of its debug output
when running in verbose mode. When mount.cifs had the setuid bit set, a
local, unprivileged user could use this flaw to disclose passwords from a
file that would otherwise be inaccessible to that user. Note: mount.cifs
from the samba packages distributed by Red Hat does not have the setuid bit
set. This flaw only affected systems where the setuid bit was manually set
by an administrator. (CVE-2009-2948)

Users of Samba should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing this update,
the smb service will be restarted automatically.";

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
 script_id(66119);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("RedHat Security Advisory RHSA-2009:1529");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:1529");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1529.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~0.18.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~0.18.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~0.18.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.0.33~0.18.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~0.18.el4_8", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~3.15.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~3.15.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~3.15.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.0.33~3.15.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~3.15.el5_4", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
