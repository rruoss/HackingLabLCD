# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2009_014_01.nasl 18 2013-10-27 14:14:13Z jan $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "New openssl packages are available for Slackware 11.0, 12.0, 12.1, 12.2,
and -current to fix a security issue when connecting to an SSL/TLS server
that uses a certificate containing a DSA or ECDSA key.

More details about this issue may be found here:
http://www.openssl.org/news/secadv_20090107.txt
http://www.ocert.org/advisories/ocert-2008-016.html
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5077";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2009-014-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-014-01";
                                                                                
if(description)
{
 script_id(63232);
 script_cve_id("CVE-2008-5077");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2009-014-01 openssl ";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution + "

";

 script_description(desc);

 script_summary("Slackware Advisory SSA:2009-014-01 openssl");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/slackpack");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-2_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-2_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-2_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-2_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl", ver:"0.9.8i-i486-2_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8i-i486-2_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}