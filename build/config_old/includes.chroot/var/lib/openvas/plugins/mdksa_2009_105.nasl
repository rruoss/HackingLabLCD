# OpenVAS Vulnerability Test
# $Id: mdksa_2009_105.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:105 (memcached)
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
tag_insight = "The process_stat function in Memcached prior 1.2.8 discloses
memory-allocation statistics in response to a stats malloc command,
which allows remote attackers to obtain potentially sensitive
information by sending this command to the daemon's TCP port
(CVE-2009-1255, CVE-2009-1494).

The updated packages have been patched to prevent this.

Affected: 2009.0, 2009.1, Corporate 4.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:105";
tag_summary = "The remote host is missing an update to memcached
announced via advisory MDVSA-2009:105.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64137);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
 script_cve_id("CVE-2009-1255", "CVE-2009-1494");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandrake Security Advisory MDVSA-2009:105 (memcached)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:105 (memcached)");

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
if ((res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.2.6~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.2.6~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.1.12~4.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
