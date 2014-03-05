# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2008_045_03.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New php-4.4.8 packages are available for Slackware 10.2 and 11.0 to
fix security issues.

More details about the issues may be found here:
http://bugs.php.net/43010";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2008-045-03.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2008-045-03";
                                                                                
if(description)
{
 script_id(60386);
 script_version("$");
 script_cve_id("CVE-2007-1285", "CVE-2007-2872", "CVE-2007-3378",
               "CVE-2007-4657", "CVE-2007-4658", "CVE-2008-0145");
 script_bugtraq_id(22764, 24261, 25498, 24661);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Slackware Advisory SSA:2008-045-03 php ";
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

 script_summary("Slackware Advisory SSA:2008-045-03 php");

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
if(isslkpkgvuln(pkg:"php", ver:"4.4.8-i486-1_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"php", ver:"4.4.8-i486-1_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
