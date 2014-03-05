###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openjpeg MDVSA-2012:104 (openjpeg)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities has been discovered and corrected in openjpeg:

  OpenJPEG allocated insufficient memory when encoding JPEG 2000 files
  from input images that have certain color depths. A remote attacker
  could provide a specially-crafted image file that, when opened in an
  application linked against OpenJPEG (such as image_to_j2k), would cause
  the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application (CVE-2009-5030).

  An input validation flaw, leading to a heap-based buffer overflow,
  was found in the way OpenJPEG handled the tile number and size in an
  image tile header. A remote attacker could provide a specially-crafted
  image file that, when decoded using an application linked against
  OpenJPEG, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application (CVE-2012-3358).

  The updated packages have been patched to correct these issues.";

tag_affected = "openjpeg on Mandriva Linux 2011.0";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:104");
  script_id(831698);
  script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-07-16 11:57:55 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2012:104");
  script_name("Mandriva Update for openjpeg MDVSA-2012:104 (openjpeg)");

  script_description(desc);
  script_summary("Check for the Version of openjpeg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libopenjpeg2", rpm:"libopenjpeg2~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenjpeg-devel", rpm:"libopenjpeg-devel~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openjpeg2", rpm:"lib64openjpeg2~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openjpeg-devel", rpm:"lib64openjpeg-devel~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
