# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2005_310_05.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New PHP packages are available for Slackware 10.2 and -current to fix minor
security issues relating to the overwriting of the GLOBALS array.

It has been reported here that this new version of PHP also breaks
squirrelmail and probably some other things.  Given the vague nature of
the security report, it's possible that the cure might be worse than the
disease as far as this upgrade is concerned.  If you encounter problems,
you may wish to drop back to 4.4.0, and I believe that doing so is
relatively safe.  I understand at least some of the issues are fixed in
CVS already, so perhaps another maintainance release is not far off.

Thanks to Gerardo Exequiel Pozzi for bringing the issues with 4.4.1 to my
attention so that this additional information could be included here.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2005-310-05.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-310-05";
                                                                                
if(description)
{
 script_id(55802);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2005-310-05 PHP ";
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

 script_summary("Slackware Advisory SSA:2005-310-05 PHP");

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
if(isslkpkgvuln(pkg:"php", ver:"4.4.1-i486-1", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}