###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_search_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Simple Search 'terms' Cross-Site Scripting Vulnerability
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
tag_affected = "Simple Search version 1.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed
  via the 'terms' parameter to 'search.cgi', that allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 20th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.scriptarchive.com/search.html";
tag_summary = "This host is running Simple Search and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(801212);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2009-4866");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Simple Search 'terms' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52311");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36178");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0908-exploits/simplesearch-xss.txt");

  script_description(desc);
  script_summary("Check if Simple Search is vulnerable to Cross-Site Scripting");
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

foreach dir (make_list("/search", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/search.html"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if(">Matt's Script Archive<" >< res)
  {
    ## Get the url of result page
    action = eregmatch(pattern: string('action="(.*cgi)">'), string: res);
    if(action[1] != NULL)
    {
      ## Construct attack request
      req = http_post(port:port, item:string(dir,"/",action[1]), data:"terms=" +
                          "%3Cscript%3Ealert%28%22OpenVASTest%22%29%3C%2Fscript" +
                          "%3E&boolean=AND&case=Insensitive");
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      ## Confirm exploit worked by checking the response
      if(('<script>alert("OpenVASTest")</script>' >< res))
      {
        security_warning(port);
        exit(0);
      }
    }
  }
}
