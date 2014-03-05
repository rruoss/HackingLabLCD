# OpenVAS Vulnerability Test
# $Id: mdksa_2009_191.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:191 (OpenEXR)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in OpenEXR:

Multiple integer overflows in OpenEXR 1.2.2 and 1.6.1
allow context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via unspecified
vectors that trigger heap-based buffer overflows, related to (1)
the Imf::PreviewImage::PreviewImage function and (2) compressor
constructors.  NOTE: some of these details are obtained from third
party information (CVE-2009-1720).

The decompression implementation in the Imf::hufUncompress function in
OpenEXR 1.2.2 and 1.6.1 allows context-dependent attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via vectors that trigger a free of an uninitialized pointer
(CVE-2009-1721).

Buffer overflow in the compression implementation in OpenEXR 1.2.2
allows context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via unspecified
vectors (CVE-2009-1722).

This update provides fixes for these vulnerabilities.

Affected: Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:191";
tag_summary = "The remote host is missing an update to OpenEXR
announced via advisory MDVSA-2009:191.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64534);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandrake Security Advisory MDVSA-2009:191 (OpenEXR)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:191 (OpenEXR)");

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
if ((res = isrpmvuln(pkg:"libOpenEXR2", rpm:"libOpenEXR2~1.2.2~3.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libOpenEXR2-devel", rpm:"libOpenEXR2-devel~1.2.2~3.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenEXR", rpm:"OpenEXR~1.2.2~3.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64OpenEXR2", rpm:"lib64OpenEXR2~1.2.2~3.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64OpenEXR2-devel", rpm:"lib64OpenEXR2-devel~1.2.2~3.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
