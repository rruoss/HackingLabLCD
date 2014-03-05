###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mini_stream_ripper_and_rmmp3_conv_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mini-Stream Ripper And RM-MP3 Converter '.pls' File Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012  Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: Application";
tag_affected = "Ripper version 3.0.1.1 and prior
  RM-MP3 Converter version 3.1.2.1";
tag_insight = "The flaw is due to an error when processing '.pls' files, which
  can be exploited to cause a stack based buffer overflow by sending specially
  crafted '.pls' file with a long entry.";
tag_solution = "No solution or patch is available as of 03rd, January 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://mini-stream.net/";
tag_summary = "This host is installed with Mini-Stream Ripper or RM-MP3 Converter
  and is prone to buffer overflow vulnerability.";

if(description)
{
  script_id(802368);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2009-5109", "CVE-2010-5081");
  script_bugtraq_id(41332, 34514);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-03 10:37:57 +0530 (Tue, 03 Jan 2012)");
  script_name("Mini-Stream Ripper And RM-MP3 Converter '.pls' File Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/61341");
  script_xref(name : "URL" , value : "http://osvdb.org/78078");
  script_xref(name : "URL" , value : "http://sebug.net/vuldb/ssvid-18793");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18082");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10782");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10747");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10745");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18113");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14373");

  script_description(desc);
  script_summary("Check for the version of Mini Stream Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_require_keys("MiniStream/RmToMp3/Conv/Ver", "MiniStream/Ripper/Ver");
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
  #Mini-stream RM-MP3 Converter 3.1.2.1 points to version 3.1.2.1.2010.03.30
  if(version_is_equal(version:rmMp3, test_version:"3.1.2.1.2010.03.30"))
  {
    security_hole(0);
    exit(0);
  }
}

miniRipper = get_kb_item("MiniStream/Ripper/Ver");
if(miniRipper)
{
  if(version_is_less_equal(version:miniRipper,test_version:"3.0.1.1")){
    security_hole(0);
  }
}
