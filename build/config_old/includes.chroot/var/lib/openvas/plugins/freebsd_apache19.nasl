#
#VID d8c901ff-0f0f-11e1-902b-20cf30e32f6d
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID d8c901ff-0f0f-11e1-902b-20cf30e32f6d
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
   apache
   apache+ssl
   apache+ipv6
   apache+mod_perl
   apache+mod_ssl
   apache+mod_ssl+ipv6
   ru-apache-1.3
   ru-apache+mod_ssl

CVE-2011-3368
The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42,
2.0.x through 2.0.64, and 2.2.x through 2.2.21 does not properly
interact with use of (1) RewriteRule and (2) ProxyPassMatch pattern
matches for configuration of a reverse proxy, which allows remote
attackers to send requests to intranet servers via a malformed URI
containing an initial @ (at sign) character.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://httpd.apache.org/security/vulnerabilities_13.html
http://seclists.org/fulldisclosure/2011/Oct/232
http://www.vuxml.org/freebsd/d8c901ff-0f0f-11e1-902b-20cf30e32f6d.html";
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
 script_id(70600);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2011-3368");
 script_tag(name:"risk_factor", value:"Medium");
 script_version("$Revision: 18 $");
 script_name("FreeBSD Ports: apache");


 script_description(desc);

 script_summary("FreeBSD Ports: apache");

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

txt = "";
vuln = 0;
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43.1.59_2")<0) {
    txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43")<0) {
    txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43")<0) {
    txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.41+2.8.31_4")<0) {
    txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.41+2.8.31_4")<0) {
    txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache-1.3");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43+30.23_1")<0) {
    txt += 'Package ru-apache-1.3 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.43+30.23_1")<0) {
    txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
