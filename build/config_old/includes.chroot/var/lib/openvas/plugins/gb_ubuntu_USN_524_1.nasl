###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openoffice.org/-amd64 vulnerability USN-524-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "An integer overflow was discovered in the TIFF handling code in OpenOffice.
  If a user were tricked into loading a malicious TIFF image, a remote attacker
  could execute arbitrary code with user privileges.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-524-1";
tag_affected = "openoffice.org/-amd64 vulnerability on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-October/000601.html");
  script_id(840063);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "524-1");
  script_cve_id("CVE-2007-2834");
  script_name( "Ubuntu Update for openoffice.org/-amd64 vulnerability USN-524-1");

  script_description(desc);
  script_summary("Check for the Version of openoffice.org/-amd64 vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libuno-cil", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-binfilter", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-us", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-andromeda", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-default", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-human", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-tango", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"broffice.org", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"2.2.0-1ubuntu5", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-evolution", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-us", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-base", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-calc", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-draw", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-gnome", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-impress", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-kde", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-math", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2-writer", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org2", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.2-2ubuntu12.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-us", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-default", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"broffice.org", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"2.0.4-0ubuntu7", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
