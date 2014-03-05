# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "A flaw in the decoding of network packets renders TCPDump vulnerable to a
remote Denial of Service attack.";
tag_solution = "All TCPDump users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/tcpdump-3.8.3-r3'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-06
http://bugs.gentoo.org/show_bug.cgi?id=90541
http://bugs.gentoo.org/show_bug.cgi?id=95349
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1267
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1278
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1279
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1280";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200505-06.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54938);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2005-1267", "CVE-2005-1278", "CVE-2005-1279", "CVE-2005-1280");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Gentoo Security Advisory GLSA 200505-06 (tcpdump)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200505-06 (tcpdump)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/gentoo");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r3"), vulnerable: make_list("lt 3.8.3-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
