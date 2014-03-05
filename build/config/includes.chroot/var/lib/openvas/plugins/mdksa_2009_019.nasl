# OpenVAS Vulnerability Test
# $Id: mdksa_2009_019.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:019 (imlib2)
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
tag_insight = "A vulnerability have been discovered in the load function of the XPM
loader for imlib2, which allows attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted XPM file
(CVE-2008-5187).

The updated packages have been patched to prevent this.

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:019";
tag_summary = "The remote host is missing an update to imlib2
announced via advisory MDVSA-2009:019.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63206);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2008-5187");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandrake Security Advisory MDVSA-2009:019 (imlib2)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:019 (imlib2)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-devel", rpm:"libimlib2_1-devel~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-devel", rpm:"lib64imlib2_1-devel~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-devel", rpm:"libimlib2_1-devel~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-devel", rpm:"lib64imlib2_1-devel~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
