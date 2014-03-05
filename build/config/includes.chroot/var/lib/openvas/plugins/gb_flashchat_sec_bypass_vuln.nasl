###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flashchat_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FlashChat Role Filter Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker bypass certain security
  restrictions and gain unauthorized administrative access to the
  affected application.";
tag_affected = "FlashChat Version 5.0.8 and prior";
tag_insight = "This flaw is due to an error in the connection.php script. By setting
  the 's' parameter to a value of '7' a remote attacker could bypass the
  role filtering mechanism.";
tag_solution = "No solution or patch is available as of 13th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer tohttp://www.tufat.com/s_flash_chat_chatroom.htm";
tag_summary = "This host is installed with FlashChat and is prone to Security
  Bypass Vulnerability.";

if(description)
{
  script_id(800616);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6799");
  script_bugtraq_id(31800);
  script_name("FlashChat Role Filter Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/49337");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32350");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45974");

  script_description(desc);
  script_summary("Check for the version of FlashChat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flashchat_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

flashport = get_http_port(default:80);
if(!flashport){
  exit(0);
}

if(!get_port_state(flashport)){
  exit(0);
}

fcVer = get_kb_item("www/" + flashport + "/FlashChat");
fcVer = eregmatch(pattern:"([0-9.]+)" ,string:fcVer);
if(fcVer[1] != NULL)
{
  if(version_is_less_equal(version:fcVer[1], test_version:"5.0.8")){
    security_hole(0);
  }
}
