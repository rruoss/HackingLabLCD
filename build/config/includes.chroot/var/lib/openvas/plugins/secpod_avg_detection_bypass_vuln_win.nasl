###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avg_detection_bypass_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# AVG AntiVirus Engine Malware Detection Bypass Vulnerability (Win)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker craft malwares in a crafted
  archive file and spread it across the network to gain access to sensitive
  information or cause damage to the remote system.
  Impact Level: System";
tag_affected = "AVG Anti-Virus prior to 8.5.323
  AVG File Server Edition prior to 8.5.323 on Windows";
tag_insight = "Error in the file parsing engine can be exploited to bypass the anti-virus
  scanning functionality via a specially crafted ZIP or RAR file.";
tag_solution = "Upgrade to the AVG Anti-Virus Scanning Engine build 8.5.323
  http://www.avg.com/download";
tag_summary = "This host is installed with AVG AntiVirus Product Suite for Windows
  and is prone to Malware Detection Bypass Vulnerability.";

if(description)
{
  script_id(900719);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1784");
  script_bugtraq_id(34895);
  script_name("AVG AntiVirus Engine Malware Detection Bypass Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50426");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/avg-zip-evasion-bypass.html");

  script_description(desc);
  script_summary("Check for the Version of AVG AntiVirus Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Remote file access");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_require_keys("AVG/AV/Win/Ver");
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

version = get_kb_item("AVG/AV/Win/Ver");
if(!version){
  exit(0);
}

#Check for AntiVirus Products Suite version prior to 8.5.323
if(version_is_less(version:version, test_version:"8.5.323")){
  security_hole(0);
}
