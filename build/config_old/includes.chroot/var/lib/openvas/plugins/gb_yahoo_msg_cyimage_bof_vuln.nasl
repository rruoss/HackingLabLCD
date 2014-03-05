###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yahoo_msg_cyimage_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Yahoo Messenger JPG Photo Sharing Integer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to a heap-based buffer
  overflow via a specially crafted JPG file.
  Impact Level: Application";
tag_affected = "Yahoo! Messenger version prior to 11.5.0.155 on Windows.";
tag_insight = "The flaw is due to an integer overflow error in the
  'CYImage::LoadJPG()' method (YImage.dll) when allocating memory using the
  image dimension values.";
tag_solution = "Upgrade to Yahoo! Messenger version 11.5.0.155 or later
  For updates refer to http://messenger.yahoo.com/download/";
tag_summary = "This host is installed with Yahoo! Messenger and is prone to
  integer overflow vulnerability.";

if(description)
{
  script_id(802419);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0268");
  script_bugtraq_id(51405);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-23 14:36:01 +0530 (Mon, 23 Jan 2012)");
  script_name("Yahoo Messenger JPG Photo Sharing Integer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47041");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0268");

  script_description(desc);
  script_summary("Check for the version of Yahoo! Messenger");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_yahoo_msg_detect.nasl");
  script_require_keys("YahooMessenger/Ver");
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

ymsgVer = get_kb_item("YahooMessenger/Ver");
if(!ymsgVer){
  exit(0);
}

# Check for Yahoo! Messenger version
if(version_is_less(version:ymsgVer, test_version:"11.5.0.0155")){
  security_hole(0);
}
