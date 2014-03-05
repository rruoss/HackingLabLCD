###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for setrlimit(1M) HPSBUX00156
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
tag_impact = "Denial of Service (DoS).";
tag_affected = "setrlimit(1M) on
  HP 9000 Series 700/800 running HP-UX B.10.01, B.10.10, B.10.20, B.10.24, 
  B.10.26 and HP-UX B.11.00, B11.04 and B.11.11 running setrlimit(1M).";
tag_insight = "A potential security vulnerability has been identifiedwith HP-UX running 
  setrlimit(1M), where setrlimit() may allow incorrect core files and cause a 
  Denial of Service (DoS).";
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
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00968563-1");
  script_id(835074);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "HPSBUX", value: "00156");
  script_name( "HP-UX Update for setrlimit(1M) HPSBUX00156");

  script_description(desc);
  script_summary("Check for the Version of setrlimit(1M)");
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

if(release == "HPUX10.01")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23512/PACHRDME/English]'], rls:"HPUX10.01")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23513'], rls:"HPUX10.01")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.10")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23477/PACHRDME/English]'], rls:"HPUX10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23478/PACHRDME/English]'], rls:"HPUX10.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23628/PACHRDME/English]'], rls:"HPUX11.00")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.24")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_24249/PACHRDME/English]'], rls:"HPUX10.24")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_24250/PACHRDME/English]'], rls:"HPUX10.24")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.26")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_25243/PACHRDME/English]'], rls:"HPUX10.26")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_25244/PACHRDME/English]'], rls:"HPUX10.26")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23886/PACHRDME/English]'], rls:"HPUX11.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.20")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_22701/PACHRDME/English]'], rls:"HPUX10.20")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_22702/PACHRDME/English]'], rls:"HPUX10.20")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"setrlimit(1M)", patch_list:['PHKL_23423/PACHRDME/English]'], rls:"HPUX11.11")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
