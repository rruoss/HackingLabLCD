###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_noticeware_mail_server_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# NoticeWare Email Server Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will let the attacker cause denial of service.

  Impact level: Application/Network";

tag_affected = "NoticeWare Mail Server version 5.1.2.2 and prior.";
tag_insight = "This flaw is due to an error when handling multiple POP3 connections. The
  server can crash when handling large number of POP3 connections issuing
  login requests.";
tag_solution = "Solution/patch not available as on 24th February 2009. For further
  updates refer, http://www.noticeware.com/noticemail.htm";
tag_summary = "This host is running NoticeWare Mail Server and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(900463);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(31697);
  script_cve_id("CVE-2008-6185");
  script_name("NoticeWare Mail Server Denial of Service Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of NoticeWare Mail Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_noticeware_mail_server_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("NoticeWare/Mail/Server/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32202");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6719");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45812");
  exit(0);
}


include("version_func.inc");

port = get_kb_item("Services/smtp");
if(!port){
  exit(0);
}

noticeVer = get_kb_item("NoticeWare/Mail/Server/Ver");
if(noticeVer != NULL)
{
  # Grep for NoticeWare Email Server version 5.1.2.2 or prior
  if(version_is_less_equal(version:noticeVer, test_version:"5.1.2.2"))
  {
    security_warning(port);
    exit(0);
  }
}
