#
#VID 4175c811-f690-4898-87c5-755b3cf1bac6
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 4175c811-f690-4898-87c5-755b3cf1bac6
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
tag_insight = "The following package is affected: ntp

CVE-2009-0159
Stack-based buffer overflow in the cookedprint function in ntpq/ntpq.c
in ntpq in NTP before 4.2.4p7-RC2 allows remote NTP servers to execute
arbitrary code via a crafted response.

CVE-2009-1252
Stack-based buffer overflow in the crypto_recv function in
ntp_crypto.c in ntpd in NTP before 4.2.4p7 and 4.2.5 before 4.2.5p74,
when OpenSSL and autokey are enabled, allows remote attackers to
execute arbitrary code via a crafted packet containing an extension
field.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.kb.cert.org/vuls/id/853097
http://www.vuxml.org/freebsd/4175c811-f690-4898-87c5-755b3cf1bac6.html";
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
 script_id(64046);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
 script_cve_id("CVE-2009-0159", "CVE-2009-1252");
 script_bugtraq_id(35017);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: ntp");


 script_description(desc);

 script_summary("FreeBSD Ports: ntp");

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
bver = portver(pkg:"ntp");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.4p7")<0) {
    txt += 'Package ntp version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
