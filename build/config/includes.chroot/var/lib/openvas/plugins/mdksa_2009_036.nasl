# OpenVAS Vulnerability Test
# $Id: mdksa_2009_036.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:036 (python)
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
tag_insight = "Multiple integer overflows in imageop.c in the imageop module in
Python 1.5.2 through 2.5.1 allow context-dependent attackers to
break out of the Python VM and execute arbitrary code via large
integer values in certain arguments to the crop function, leading to
a buffer overflow, a different vulnerability than CVE-2007-4965 and
CVE-2008-1679. (CVE-2008-4864)

Multiple integer overflows in Python 2.5.2 and earlier allow
context-dependent attackers to have an unknown impact via vectors
related to the (1) stringobject, (2) unicodeobject, (3) bufferobject,
(4) longobject, (5) tupleobject, (6) stropmodule, (7) gcmodule, and
(8) mmapmodule modules. NOTE: The expandtabs integer overflows in
stringobject and unicodeobject in 2.5.2 are covered by CVE-2008-5031.

Multiple integer overflows in Python 2.2.3 through 2.5.1, and 2.6,
allow context-dependent attackers to have an unknown impact via
a large integer value in the tabsize argument to the expandtabs
method, as implemented by (1) the string_expandtabs function in
Objects/stringobject.c and (2) the unicode_expandtabs function in
Objects/unicodeobject.c. NOTE: this vulnerability reportedly exists
because of an incomplete fix for CVE-2008-2315. (CVE-2008-5031)

The updated Python packages have been patched to correct these issues.

Affected: Corporate 3.0, Multi Network Firewall 2.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:036";
tag_summary = "The remote host is missing an update to python
announced via advisory MDVSA-2009:036.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63373);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
 script_cve_id("CVE-2007-4965", "CVE-2008-1679", "CVE-2008-4864", "CVE-2008-5031", "CVE-2008-2315");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Mandrake Security Advisory MDVSA-2009:036 (python)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:036 (python)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libpython2.3", rpm:"libpython2.3~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3-devel", rpm:"libpython2.3-devel~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64python2.3", rpm:"lib64python2.3~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64python2.3-devel", rpm:"lib64python2.3-devel~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3", rpm:"libpython2.3~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3-devel", rpm:"libpython2.3-devel~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
