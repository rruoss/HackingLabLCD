###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for msec MDVA-2010:148 (msec)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "msec on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_insight = "This update fixes a number of issues in msec:
  - this update fixes incorrect German localization for msecperms
  messages (bug #51005)
  - this update allows to import legacy perm.local permissions
  configuration file, which could be installed by third-party
  applications
  - this update fixes a crash when pam_unix is used together with msec
  (bug #58018). Note that this configuration is not used by Mandriva
  Linux usually, but can be employed in some custom environments.
  - this update adds a IGNORE_PID_CHANGES variable to filter changes
  in process PIDs when reporting changes in network configuration (bug
  #56744). To use this functionality, add a IGNORE_PID_CHANGES=yes into
  /etc/security/msec/security.conf, and changes in listening network
  ports will be ignored during periodic checks.
  - this update fixes an issue when chkrootkit results were not properly
  excluded by the exceptions list (bug #58076)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-05/msg00015.php");
  script_id(831041);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-17 16:00:10 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVA", value: "2010:148");
  script_name("Mandriva Update for msec MDVA-2010:148 (msec)");

  script_description(desc);
  script_summary("Check for the Version of msec");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"msec", rpm:"msec~0.70.13~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"msec-gui", rpm:"msec-gui~0.70.13~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
