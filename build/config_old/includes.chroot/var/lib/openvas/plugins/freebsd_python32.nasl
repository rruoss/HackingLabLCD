#
#VID b4f8be9e-56b2-11e1-9fb7-003067b2972c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID b4f8be9e-56b2-11e1-9fb7-003067b2972c
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
   python32
   python31
   python27
   python26
   python25
   python24
   pypy";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://bugs.python.org/issue14001
https://bugzilla.redhat.com/show_bug.cgi?id=789790
https://bugs.pypy.org/issue1047
http://www.vuxml.org/freebsd/b4f8be9e-56b2-11e1-9fb7-003067b2972c.html";
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
 script_id(71172);
 script_cve_id("CVE-2012-0845");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
 script_name("FreeBSD Ports: python32");

 script_description(desc);

 script_summary("FreeBSD Ports: python32");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
vuln = 0;
txt = "";
bver = portver(pkg:"python32");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.2_2")<=0) {
    txt += "Package python32 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"python31");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.4_2")<=0) {
    txt += "Package python31 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"python27");
if(!isnull(bver) && revcomp(a:bver, b:"2.7.2_3")<=0) {
    txt += "Package python27 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"python26");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.7_2")<=0) {
    txt += "Package python26 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"python25");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.6_2")<=0) {
    txt += "Package python25 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"python24");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5_8")<=0) {
    txt += "Package python24 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"pypy");
if(!isnull(bver) && revcomp(a:bver, b:"1.7")<=0) {
    txt += "Package pypy version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
