###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_slurm_privilege_escalation_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Privilege Escalation Vulnerability in SLURM
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "This can be exploited by malicious SLURM local users to gain escalated
  privileges.
  Impact Level: Application/System";
tag_affected = "SLURM all versions of 1.2 and 1.3 prior to 1.3.15 on Linux (Debian)";
tag_insight = "- Error within the sbcast implementation when establishing supplemental
    groups, which can be exploited to e.g. access files with the supplemental
    group privileges of the slurmd daemon.
  - Error in slurmctld daemon is not properly dropping supplemental groups
    when handling the 'strigger' command, which can be exploited to
    e.g. access files with the supplemental group privileges of the
    slurmctld daemon.";
tag_solution = "Upgrade to SLURM version 1.3.14 or later
  https://computing.llnl.gov/linux/slurm/download.html";
tag_summary = "This host has SLURM (Simple Linux Utility for Resource Management)
  installed and is prone to Privilege Escalation vulnerability.";

if(description)
{
  script_id(900375);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2084");
  script_bugtraq_id(34638);
  script_name("Privilege Escalation Vulnerability in SLURM");
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
  script_xref(name : "URL" , value : "http://www.debian.org/security/2009/dsa-1776");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1128");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=524980");
  script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=676055&amp;group_id=157944");

  script_description(desc);
  script_summary("Check for the version of SLURM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_slurm_detect.nasl");
  script_require_keys("SLURM/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

# Check for SLURM all versions of 1.2 and 1.3 prior to 1.3.15
slurmVer = get_kb_item("SLURM/Ver");
if(slurmVer)
{
  if(version_in_range(version:slurmVer, test_version:"1.2", test_version2:"1.3.13")){
    security_hole(0);
  }
}
