###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dell_webcam_activex_mult_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Dell Webcam 'crazytalk4.ocx' ActiveX Multiple BOF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application using the ActiveX control.
  Impact Level: System/Application";
tag_affected = "Dell Webcam";
tag_insight = "The flaws are due to boundary error when processing user-supplied
  input.";
tag_solution = "No solution or patch is available as of 29th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://search.dell.com/results.aspx?c=us&l=en&s=basd&cat=cmu&k=dell+webcam+central";
tag_summary = "This host is installed with Dell Webcam and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(903013);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52571, 52560);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-29 14:38:14 +0530 (Thu, 29 Mar 2012)");
  script_name("Dell Webcam 'crazytalk4.ocx' ActiveX Multiple BOF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52571/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52560/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18621/");

  script_description(desc);
  script_summary("Check for the CLSID of Dell Webcam ActiveX Control");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check if Kill-Bit is set
if(is_killbit_set(clsid:"{13149882-F480-4F6B-8C6A-0764F75B99ED}") == 0){
  security_hole(0);
}
