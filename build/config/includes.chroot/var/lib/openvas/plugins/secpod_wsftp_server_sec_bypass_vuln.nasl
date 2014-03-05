###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_wsftp_server_sec_bypass_vuln.nasl 738 2008-12-22 15:30:29Z dec $
#
# WS_FTP Server Manager Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  compressed rar achive and can cause memory corruption or buffer overflows.";
tag_affected = "Ipswitch WS_FTP Server version 6.1.0.0 and prior versions.";
tag_insight = "This flaw is due to
  - an error within the WS_FTP Server Manager when processing HTTP requests for
    the FTPLogServer/LogViewer.asp script.
  - less access control in custom ASP Files in WSFTPSVR/ via a request with the
    appended dot characters which causes disclosure of .asp file contents.";
tag_solution = "Upgrade to the latest version 6.1.1 or higher.
  http://www.ipswitchft.com/products/ws_ftp_server";
tag_summary = "This host is installed with WS_FTP Server and is prone to Security
  Bypass Vulnerability.";

if(description)
{
  script_id(900451);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5692", "CVE-2008-5693");
  script_bugtraq_id(27654);
  script_name("WS_FTP Server Manager Security Bypass Vulnerability");
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
  script_summary("Check for the version of Ipswitch WS_FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28822");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/wsftpweblog-adv.txt");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5692");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5693");
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("WS_FTP Server" >!< banner){
  exit(0);
}

wsVer = eregmatch(pattern:"WS_FTP Server ([0-9.]+)", string:banner);
if(wsVer[1] != NULL)
{
  # Grep for version 6.1.0.0 and prior 
  if(version_is_less_equal(version:wsVer[1], test_version:"6.1.0.0")){
    security_warning(port);
  }
}
