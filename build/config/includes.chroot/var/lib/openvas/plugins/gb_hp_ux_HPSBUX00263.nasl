###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for CDE HPSBUX00263
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
tag_impact = "Remote unauthorized privileged access and execution of arbitrary code.";
tag_affected = "CDE on
  HP-UX B.10.20, B.11.00, B.11.04, B.11.11, and B.11.22 running CDE.";
tag_insight = "A potential security vulnerability has been identified with HP UX, running 
  CDE libraries and programs could be remotely exploited to gain unauthorized 
  privileged access and execute arbitrary code.";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00957810-1");
  script_id(835014);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "HPSBUX", value: "00263");
  script_name( "HP-UX Update for CDE HPSBUX00263");

  script_description(desc);
  script_summary("Check for the Version of CDE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:hp:hp-ux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.22")
{

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-SHLIBS", patch_list:['PHSS_28682'], rls:"HPUX11.22")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-RUN", patch_list:['PHSS_28683'], rls:"HPUX11.22")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-SHLIBS", patch_list:['PHSS_28675'], rls:"HPUX11.00")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-RUN", patch_list:['PHSS_28675'], rls:"HPUX11.00")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDEDevKit.CDE-PRG", patch_list:['PHSS_28678'], rls:"HPUX11.00")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-SHLIBS", patch_list:['PHSS_29214'], rls:"HPUX11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-RUN", patch_list:['PHSS_29214'], rls:"HPUX11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.20")
{

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-SHLIBS", patch_list:['PHSS_29201'], rls:"HPUX10.20")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-RUN", patch_list:['PHSS_29201'], rls:"HPUX10.20")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDEDevKit.CDE-PRG", patch_list:['PHSS_29202'], rls:"HPUX10.20")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-SHLIBS", patch_list:['PHSS_28676'], rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDE.CDE-RUN", patch_list:['PHSS_28677'], rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"CDEDevKit.CDE-PRG", patch_list:['PHSS_28679'], rls:"HPUX11.11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
