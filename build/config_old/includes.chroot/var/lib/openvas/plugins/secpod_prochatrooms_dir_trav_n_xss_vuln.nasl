###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_prochatrooms_dir_trav_n_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Directory Traversal And XSS Vulnerability In Pro Chat Rooms
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could result in Directory Traversal, Cross-Site
  Scripting or Cross-Site Request Forgery attack by execute arbitrary HTML
  and script code on the affected application.
  Impact Level: Application";
tag_affected = "Pro Chat Rooms version 3.0.3 and prior on all running platform.";
tag_insight = "- Error in profiles/index.php and profiles/admin.php file allows remote
    attackers to inject arbitrary web script or HTML via the 'gud' parameter.
  - Error in sendData.php file allows remote authenticated users to select
    an arbitrary local PHP script as an avatar via a ..(dot dot) in the
    'avatar' parameter.";
tag_solution = "Upgrade to Pro Chat Rooms version 6.0 or later,
  For updates refer to http://www.prochatrooms.com";
tag_summary = "This host is running Pro Chat Rooms and is prone to Directory
  Traversal and XSS vulnerability.";

if(description)
{
  script_id(900331);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6501", "CVE-2008-6502");
  script_bugtraq_id(32758);
  script_name("Directory Traversal And XSS Vulnerability In Pro Chat Rooms");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33088");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6612");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7409");

  script_description(desc);
  script_summary("Check for the version or XSS in Pro Chat Rooms");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_prochatrooms_detect.nasl");
  script_require_ports("Services/www", 80);
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
include("http_func.inc");
include("http_keepalive.inc");

pcrPort = get_kb_item("Services/www");
if(!pcrPort){
  exit(0);
}

if(!safe_checks())
{
  # XSS attack string test in 'gud' parameter inside 'index.php' and
  # 'admin.php' file
  sndReq = string("GET /prochatrooms/profiles/index.php?gud=XSSED\r\n",
                   "Host: ", get_host_name(), "\r\n\r\n");

  rcvRes = http_keepalive_send_recv(port:pcrPort, data:sndReq);
  if(rcvRes == NULL)
  {
    sndReq = string("GET /prochatrooms/profiles/admin.php?gud=XSSED\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
    rcvRes = http_keepalive_send_recv(port:pcrPort, data:sndReq);
    if(rcvRes == NULL){
      exit(0);
    }
  }

  if("XSSED" >< rcvRes && rcvRes =~ "HTTP/1\.[0-9]+ 200")
  {
    security_warning(pcrPort);
    exit(0);
  }
}

pcrVer = get_kb_item("www/"+ pcrPort + "/ProChatRooms");
if(!pcrVer){
  exit(0);
}

# Check for version 3.0.3 and prior
if(version_is_less_equal(version:pcrVer, test_version:"3.0.3")){
  security_warning(pcrPort);
}
