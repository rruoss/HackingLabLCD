###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yahoo_msg_actvx_ctrl_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Yahoo! Messenger 'YahooBridgeLib.dll' ActiveX Control DOS Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to cause Denial of
  Service condition on the affected applicaion.
  Impact Level: Application";
tag_affected = "Yahoo! Messenger version 9.x to 9.0.0.2162 on Windows.";
tag_insight = "The flaw is due to a NULL pointer dereference error in 'RegisterMe()' method
  in 'YahooBridgeLib.dll', which can be exploited by causing victim to visit a
  specially crafted Web page.";
tag_solution = "Upgrade to Yahoo! Messenger version 10.0.0.1270 or later
  For updates refer to http://messenger.yahoo.com/download/";
tag_summary = "This host is installed with Yahoo! Messenger and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(801150);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4171");
  script_bugtraq_id(37007);
  script_name("Yahoo! Messenger 'YahooBridgeLib.dll' ActiveX Control DOS Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54263");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507818/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Yahoo! Messenger");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_yahoo_msg_detect.nasl", "yahoo_msg_running.nasl");
  script_require_keys("YahooMessenger/Ver");
  script_require_ports("Services/yahoo_messenger");
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

ymsgPort = get_kb_item("Services/yahoo_messenger");
if(!ymsgPort){
  ymsgPort = 5101;
}

if(!get_port_state(ymsgPort)){
  exit(0);
}

ymsgVer = get_kb_item("YahooMessenger/Ver");
if(!ymsgVer){
  exit(0);
}

# Check for Yahoo! Messenger version 9.x to 9.0.0.2162
if(version_in_range(version:ymsgVer, test_version:"9.0", test_version2:"9.0.0.2162")){
  security_warning(ymsgPort);
}
