###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_mult_prdts_bof_may09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mini-Stream Multiple Products Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker craft malicious 'asx' or 'ram'
  files and execute arbitrary codes to cause stack overflow in the context of
  the affected application.
  Impact Level: Application";
tag_affected = "Ripper version 3.0.1.1 (3.0.1.5) and prior
  RM-MP3 Converter version 3.0.0.7 and prior
  ASXtoMP3 Converter version 3.0.0.7 and prior";
tag_insight = "Inadequate boundary checks error of user supplied input to Mini-stream products
  which causes stack overflow while processing .ram and .asx files with overly
  long URIs.";
tag_solution = "No solution or patch is available as of 26th May,2009. Information
  regarding This issue will be updated once the solution details are available.
  For updates refer tohttp://www.mini-stream.net";
tag_summary = "This host has Mini-Stream products installed and is prone to Stack Overflow
  Vulnerability.";

if(description)
{
  script_id(900646);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1642", "CVE-2009-1641", "CVE-2009-1645");
  script_bugtraq_id(34864);
  script_name("Mini-Stream Multiple Products Stack Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8629");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8630");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8633");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8632");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8631");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50374");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50375");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50376");

  script_description(desc);
  script_summary("Check for the version of Mini Stream Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_require_keys("MiniStream/RmToMp3/Conv/Ver",
                      "MiniStream/AsxToMp3/Conv/Ver", "MiniStream/Ripper/Ver");
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

rmMp3 = get_kb_item("MiniStream/RmToMp3/Conv/Ver");
if(rmMp3)
{
  if(version_is_less_equal(version:rmMp3, test_version:"3.0.0.7"))
  {
    security_hole(0);
  }
}

asxMp3 = get_kb_item("MiniStream/AsxToMp3/Conv/Ver");
if(asxMp3)
{
  if(version_is_less_equal(version:asxMp3, test_version:"3.0.0.7"))
  {
    security_hole(0);
  }
}

ripper = get_kb_item("MiniStream/Ripper/Ver");
if(ripper)
{
  #Ministream ripper 3.0.1.1 points to the version 3.0.1.5
  if(version_is_less_equal(version:ripper,test_version:"3.0.1.5"))
  {
    security_hole(0);
  }
}