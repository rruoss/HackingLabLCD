###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcollab_http_resp_splitting_vuln.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# WebCollab 'item' Parameter HTTP Response Splitting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803773";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_bugtraq_id(63247);
  script_cve_id("CVE-2013-2652");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 15:46:55 +0530 (Mon, 28 Oct 2013)");
  script_name("WebCollab 'item' Parameter HTTP Response Splitting Vulnerability");

  tag_summary =
"This host is installed with WebCollab and is prone to HTTP response splitting
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to inject malicious data in header or not.";

  tag_insight =
"Input passed via the 'item' GET parameter to help/help_language.php is not
properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attackers to insert arbitrary HTTP
headers, which will be included in a response sent to the user.

Impact Level: Application";

  tag_affected =
"WebCollab versions 3.30 and prior.";

  tag_solution =
"Upgrade to WebCollab 3.31 or later,
For updates refer to http://webcollab.sourceforge.net ";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/98768");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55235");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/119");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123771");
  script_xref(name : "URL" , value : "http://freecode.com/projects/webcollab/releases/358621");
  script_xref(name : "URL" , value : "http://sourceforge.net/p/webcollab/mailman/message/31536457");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/webcollab-330-http-response-splitting");

  script_summary("Check if WebCollab is vulnerable to HTTP response splitting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/webcollab", "/WebCollab", cgi_dirs()))
{
   req = http_get(item:string(dir, "/index.php"),  port: http_port);
   res = http_keepalive_send_recv(port:http_port, data:req);

   ## confirm the Application
   if(res && egrep(pattern:">WebCollab<", string:res))
   {
     ## Construct Attack Request
     url = dir + '/help/help_language.php?item=%0d%0a%20FakeHeader%3a%20' +
           'Fakeheaderis%20injected&amp;lang=en&amp;type=help';

     ## Check the response to confirm vulnerability
     if(http_vuln_check(port:http_port, url:url, pattern:"FakeHeader: Fakeheaderis injected",
       extra_check:">WebCollab<"))
     {
       security_warning(http_port);
       exit(0);
     }
  }
}
