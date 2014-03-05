##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netartmedia_websiteadmin_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# NetArtMedia WebSiteAdmin Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to include and execute arbitrary
  local files via directory traversal sequences in the lng parameter.
  Impact Level: Application.";
tag_affected = "NetArtMedia WebSiteAdmin version 2.1";

tag_insight = "The flaw exists due to input passed via the 'lng' parameter to
  'ADMIN/login.php' is not properly validating before returning to the user.";
tag_solution = "No solution or patch is available as of 01st October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.websiteadmin.biz/";
tag_summary = "This host is running NetArtMedia WebSiteAdmin and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(801518);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-3688");
  script_name("NetArtMedia WebSiteAdmin Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://vul.hackerjournals.com/?p=12826");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/398140.php");
  script_xref(name : "URL" , value : "http://pridels-team.blogspot.com/2010/09/netartmedia-real-estate-portal-v20-xss.html");

  script_description(desc);
  script_summary("Check through Directory Traversal attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");


## Get HTTP port
wsaPort = get_http_port(default:80);
if(!wsaPort){
  exit(0);
}

foreach dir (make_list("/websiteadmin", "/WebSiteAdmin", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/index.php"), port:wsaPort);
  rcvRes = http_send_recv(port:wsaPort, data:sndReq);

  ## Confirm application is NetArtMedia WebSiteAdmin
  if(">NetArt" >< rcvRes && ">WebSiteAdmin<" >< rcvRes)
  {
    ## Try Exploit
    sndReq = http_get(item:string(dir, '/ADMIN/login.php?lng=../../'), port:wsaPort);
    rcvRes = http_send_recv(port:wsaPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if(': failed to open stream:' >< rcvRes && 'No such file or directory' >< rcvRes)
    {
      security_hole(wsaPort);
      exit(0);
    }
  }
}
