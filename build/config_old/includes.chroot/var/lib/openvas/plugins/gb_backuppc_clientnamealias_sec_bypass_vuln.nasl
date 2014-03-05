###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_backuppc_clientnamealias_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# BackupPC 'ClientNameAlias' Function Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "No solution or patch is available as of 06th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://backuppc.sourceforge.net/
  or
  For Debian platform Update to version 3.1.0-7 from below link,
  https://launchpad.net/debian/+source/backuppc/3.1.0-7
  http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=542218

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful attacks may allow remote authenticated users to read and write
  sensitive files by modifying ClientNameAlias to match another system, then
  initiating a backup or restore on the victim's system.
  Impact Level: System";
tag_affected = "BackupPC version 3.1.0 and prior.";
tag_insight = "The security issue is due to the application allowing users to set the
  'ClientNameAlias' option for configured hosts. This can be exploited to backup
  arbitrary directories from client systems for which Rsync over SSH is
  configured as a transfer method.";
tag_summary = "This host has BackupPC intallation and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(801107);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3369");
  script_name("BackupPC 'ClientNameAlias' Function Security Bypass Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://osvdb.org/57236");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36393");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=542218");

  script_description(desc);
  script_summary("Check for the version of BackupPC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_backuppc_detect.nasl");
  script_require_keys("BackupPC/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

backuppcVer = get_kb_item("BackupPC/Ver");
if(backuppcVer)
{
  # Check for BackupPC version <= 3.1.0
  if(version_in_range(version:backuppcVer, test_version:"3.0",
                                           test_version2:"3.1.0")){
     security_hole(0);
  }
}
