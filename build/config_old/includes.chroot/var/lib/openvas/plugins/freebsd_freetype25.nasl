#
#VID 462e2d6c-8017-11e1-a571-bcaec565249c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 462e2d6c-8017-11e1-a571-bcaec565249c
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
tag_insight = "The following package is affected: freetype2

CVE-2012-1126
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a BDF
font.
CVE-2012-1127
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font.
CVE-2012-1128
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (NULL pointer dereference and memory corruption) or possibly
execute arbitrary code via a crafted TrueType font.
CVE-2012-1129
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted SFNT string in a Type 42
font.
CVE-2012-1130
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a PCF
font.
CVE-2012-1131
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, on 64-bit platforms allows remote attackers to
cause a denial of service (invalid heap read operation and memory
corruption) or possibly execute arbitrary code via vectors related to
the cell table of a font.
CVE-2012-1132
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted dictionary data in a Type
1 font.
CVE-2012-1133
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font.
CVE-2012-1134
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted private-dictionary data in
a Type 1 font.
CVE-2012-1135
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via vectors involving the NPUSHB and
NPUSHW instructions in a TrueType font.
CVE-2012-1136
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font that lacks an ENCODING field.
CVE-2012-1137
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted header in a BDF font.
CVE-2012-1138
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via vectors involving the MIRP
instruction in a TrueType font.
CVE-2012-1139
Array index error in FreeType before 2.4.9, as used in Mozilla Firefox
Mobile before 10.0.4 and other products, allows remote attackers to
cause a denial of service (invalid stack read operation and memory
corruption) or possibly execute arbitrary code via crafted glyph data
in a BDF font.
CVE-2012-1140
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted PostScript font object.
CVE-2012-1141
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted ASCII string in a BDF
font.
CVE-2012-1142
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph-outline data in a
font.
CVE-2012-1143
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (divide-by-zero error) via a crafted font.
CVE-2012-1144
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via a crafted TrueType font.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://sourceforge.net/projects/freetype/files/freetype2/2.4.9/README/view
https://bugzilla.redhat.com/show_bug.cgi?id=806270
http://www.vuxml.org/freebsd/462e2d6c-8017-11e1-a571-bcaec565249c.html";
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
 script_id(71283);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
 script_name("FreeBSD Ports: freetype2");

 script_description(desc);

 script_summary("FreeBSD Ports: freetype2");

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
bver = portver(pkg:"freetype2");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.9")<0) {
    txt += "Package freetype2 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
