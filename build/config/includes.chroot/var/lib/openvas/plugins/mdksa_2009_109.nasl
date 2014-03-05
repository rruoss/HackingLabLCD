# OpenVAS Vulnerability Test
# $Id: mdksa_2009_109.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:109 (quagga)
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
tag_insight = "The BGP daemon (bgpd) in Quagga 0.99.11 and earlier allows remote
attackers to cause a denial of service (crash) via an AS path
containing ASN elements whose string representation is longer than
expected, which triggers an assert error (CVE-2009-1572).

Updated packages are available that bring Quagga to version 0.99.12
which provides numerous bugfixes over the previous 0.99.9 version,
and also corrects this issue.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:109";
tag_summary = "The remote host is missing an update to quagga
announced via advisory MDVSA-2009:109.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63951);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-1572");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandrake Security Advisory MDVSA-2009:109 (quagga)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:109 (quagga)");

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
if ((res = isrpmvuln(pkg:"libquagga0", rpm:"libquagga0~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libquagga0-devel", rpm:"libquagga0-devel~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64quagga0", rpm:"lib64quagga0~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64quagga0-devel", rpm:"lib64quagga0-devel~0.99.12~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
