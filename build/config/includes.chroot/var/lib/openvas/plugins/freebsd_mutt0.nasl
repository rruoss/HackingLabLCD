#
#VID d2a43243-087b-11db-bc36-0008743bf21a
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
   mutt
   mutt-lite
   mutt-devel
   mutt-devel-lite
   ja-mutt
   zh-mutt-devel
   ja-mutt-devel
   mutt-ng";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://dev.mutt.org/cgi-bin/gitweb.cgi?p=mutt/.git;a=commit;h=dc0272b749f0e2b102973b7ac43dbd3908507540
http://www.vuxml.org/freebsd/d2a43243-087b-11db-bc36-0008743bf21a.html";
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
 script_id(57068);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-3242");
 script_bugtraq_id(18642);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: mutt, mutt-lite");


 script_description(desc);

 script_summary("FreeBSD Ports: mutt, mutt-lite");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"mutt");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.1_2")<=0) {
    txt += 'Package mutt version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mutt-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.1_2")<=0) {
    txt += 'Package mutt-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mutt-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.11_2")<=0) {
    txt += 'Package mutt-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mutt-devel-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.11_2")<=0) {
    txt += 'Package mutt-devel-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-mutt");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.1.j1")<=0) {
    txt += 'Package ja-mutt version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-mutt-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.11_20040617")<=0) {
    txt += 'Package zh-mutt-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-mutt-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.6.j1_2")<=0) {
    txt += 'Package ja-mutt-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"mutt-ng");
if(!isnull(bver) && revcomp(a:bver, b:"20060501")<=0) {
    txt += 'Package mutt-ng version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
