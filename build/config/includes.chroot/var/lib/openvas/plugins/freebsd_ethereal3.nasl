#
#VID 74d06b67-d2cf-11d8-b479-02e0185c0b53
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

CVE-2004-0504
Ethereal 0.10.3 allows remote attackers to cause a denial of service
(crash) via certain SIP messages between Hotsip servers and clients.

CVE-2004-0505
The AIM dissector in Ethereal 0.10.3 allows remote attackers to cause
a denial of service (assert error) via unknown attack vectors.

CVE-2004-0506
The SPNEGO dissector in Ethereal 0.9.8 to 0.10.3 allows remote
attackers to cause a denial of service (crash) via unknown attack
vectors that cause a null pointer dereference.

CVE-2004-0507
Buffer overflow in the MMSE dissector for Ethereal 0.10.1 to 0.10.3
allows remote attackers to cause a denial of service and possibly
execute arbitrary code.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ethereal.com/appnotes/enpa-sa-00014.html
http://secunia.com/advisories/11608
http://www.osvdb.org/6131
http://www.osvdb.org/6132
http://www.osvdb.org/6133
http://www.osvdb.org/6134
http://www.vuxml.org/freebsd/74d06b67-d2cf-11d8-b479-02e0185c0b53.html";
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
 script_id(52433);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0504", "CVE-2004-0505", "CVE-2004-0506", "CVE-2004-0507");
 script_bugtraq_id(10347);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
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
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
    txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
    txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
    txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
    txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
