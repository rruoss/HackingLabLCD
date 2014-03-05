#
#VID slesp1-java-1_4_2-ibm-5182
# OpenVAS Vulnerability Test
# $
# Description: Security update for IBM Java 1.4.2
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    java-1_4_2-ibm
    java-1_4_2-ibm-devel
    java-1_4_2-ibm-jdbc
    java-1_4_2-ibm-plugin


More details may also be found by searching for the SuSE
Enterprise Server 10 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(65988);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2008-1196", "CVE-2008-1195", "CVE-2008-1192", "CVE-2008-1190", "CVE-2008-1189", "CVE-2008-1187", "CVE-2007-5232", "CVE-2007-5274", "CVE-2007-5273", "CVE-2007-5236", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-4381", "CVE-2007-3698");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SLES10: Security update for IBM Java 1.4.2");


 script_description(desc);

 script_summary("SLES10: Security update for IBM Java 1.4.2");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if ((res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr10~0.2", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-devel", rpm:"java-1_4_2-ibm-devel~1.4.2_sr10~0.2", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr10~0.2", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr10~0.2", rls:"SLES10.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}