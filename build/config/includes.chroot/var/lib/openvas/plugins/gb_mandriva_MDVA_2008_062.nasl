###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for drakxtools MDVA-2008:062 (drakxtools)
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
tag_insight = "This update fixes several minor issues:

  - some GUIes (eg: rpmdrake) would crash on clicking on the close
  button while they load (bug #35230)
  
  - draksec was crashing if the administrator refused to install
  (bug #38911)
  
  - localdrake: After changing the localization language from drakconf
  in a high security level, the permissions of /etc/sysconfig/i18n were
  changed such that the file was only readable by root.  This caused
  graphical login via kdm to fail (bug #39027)";

tag_affected = "drakxtools on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-05/msg00013.php");
  script_id(830759);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:05:19 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVA", value: "2008:062");
  script_name( "Mandriva Update for drakxtools MDVA-2008:062 (drakxtools)");

  script_description(desc);
  script_summary("Check for the Version of drakxtools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"drakx-finish-install", rpm:"drakx-finish-install~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakxtools", rpm:"drakxtools~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakxtools-backend", rpm:"drakxtools-backend~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakxtools-curses", rpm:"drakxtools-curses~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakxtools-http", rpm:"drakxtools-http~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"harddrake", rpm:"harddrake~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"harddrake-ui", rpm:"harddrake-ui~10.4.239.5~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
