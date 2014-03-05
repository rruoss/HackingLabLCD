#
#VID defce068-39aa-11de-a493-001b77d09812
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID defce068-39aa-11de-a493-001b77d09812
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
tag_insight = "The following packages are affected:
   wireshark
   wireshark-lite

CVE-2009-1210
Format string vulnerability in the PROFINET/DCP (PN-DCP) dissector in
Wireshark 1.0.6 and earlier allows remote attackers to execute
arbitrary code via a PN-DCP packet with format string specifiers in
the station name.  NOTE: some of these details are obtained from third
party information.

CVE-2009-1268
The Check Point High-Availability Protocol (CPHAP) dissector in
Wireshark 0.9.6 through 1.0.6 allows remote attackers to cause a
denial of service (crash) via a crafted FWHA_MY_STATE packet.

CVE-2009-1269
Unspecified vulnerability in Wireshark 0.99.6 through 1.0.6 allows
remote attackers to cause a denial of service (crash) via a crafted
Tektronix .rf5 file.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.wireshark.org/security/wnpa-sec-2009-02.html
http://www.vuxml.org/freebsd/defce068-39aa-11de-a493-001b77d09812.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63966);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
 script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269");
 script_bugtraq_id(34291,34457);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: wireshark, wireshark-lite");


 script_description(desc);

 script_summary("FreeBSD Ports: wireshark, wireshark-lite");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.6")>=0 && revcomp(a:bver, b:"1.0.7")<0) {
    txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.6")>=0 && revcomp(a:bver, b:"1.0.7")<0) {
    txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
