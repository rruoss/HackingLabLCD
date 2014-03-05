#
#VID cb470368-94d2-11d9-a9e0-0001020eed82
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
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
tag_insight = "The following packages are affected:
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2005-0699
Multiple buffer overflows in the dissect_a11_radius function in the
CDMA A11 (3G-A11) dissector (packet-3g-a11.c) for Ethereal 0.10.9 and
earlier allow remote attackers to execute arbitrary code via RADIUS
authentication packets with large length values.

CVE-2005-0704
Buffer overflow in the Etheric dissector in Ethereal 0.10.7 through
0.10.9 allows remote attackers to cause a denial of service
(application crash) and possibly execute arbitrary code.

CVE-2005-0705
The GPRS-LLC dissector in Ethereal 0.10.7 through 0.10.9, with the
'ignore cipher bit' option enabled. allows remote attackers to cause a
denial of service (application crash).

CVE-2005-0739
The IAPP dissector (packet-iapp.c) for Ethereal 0.9.1 to 0.10.9 does
not properly use certain routines for formatting strings, which could
leave it vulnerable to buffer overflows, as demonstrated using
modified length values that are not properly handled by the the
dissect_pdus and pduval_to_str functions.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ethereal.com/appnotes/enpa-sa-00018.html
http://www.vuxml.org/freebsd/cb470368-94d2-11d9-a9e0-0001020eed82.html";
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
 script_id(52156);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: ethereal, ethereal-lite, tethereal, tethereal-lite");


 script_description(desc);

 script_summary("FreeBSD Ports: ethereal, ethereal-lite, tethereal, tethereal-lite");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
    txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
    txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
    txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
    txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
