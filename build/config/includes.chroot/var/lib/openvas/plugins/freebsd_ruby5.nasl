#
#VID a8674c14-83d7-11db-88d5-0012f06707f0
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
   ruby
   ruby+pthreads
   ruby+pthreads+oniguruma
   ruby+oniguruma
   ruby_static";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.ruby-lang.org/en/news/2006/12/04/another-dos-vulnerability-in-cgi-library/
http://www.vuxml.org/freebsd/a8674c14-83d7-11db-88d5-0012f06707f0.html";
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
 script_id(57674);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-6303");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: ruby");


 script_description(desc);

 script_summary("FreeBSD Ports: ruby");

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
bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.5_5,1")<0) {
    txt += 'Package ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+pthreads");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.5_5,1")<0) {
    txt += 'Package ruby+pthreads version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+pthreads+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.5_5,1")<0) {
    txt += 'Package ruby+pthreads+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby+oniguruma");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0 && revcomp(a:bver, b:"1.8.5_5,1")<0) {
    txt += 'Package ruby+oniguruma version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ruby_static");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,1")>=0) {
    txt += 'Package ruby_static version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}