###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activemq_xss_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache ActiveMQ Persistent Cross-Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "Apache ActiveMQ 5.3 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'JMSDestination' parameter to createDestination.action that allows the
  attackers to insert arbitrary HTML and script code.";
tag_solution = "Upgrade to the latest version of ActiveMQ 5.3.1 or later,
  For updates refer to http://activemq.apache.org";
tag_summary = "This host is running Apache ActiveMQ and is prone to cross-site
  scripting and cross-site request forgery vulnerabilities.";

if(description)
{
  script_id(801203);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1244","CVE-2010-0684");
  script_bugtraq_id(39119);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Apache ActiveMQ Persistent Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57398");
  script_xref(name : "URL" , value : "http://www.rajatswarup.com/CVE-2010-0684.txt");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39223");
  script_xref(name : "URL" , value : "https://issues.apache.org/activemq/browse/AMQ-2625");

  script_description(desc);
  script_summary("Check if ActiveMQ is vulnerable to XSS and XSRF");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8161);
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

## Get ActiveMQ Port
port = get_http_port(default:8161);
if(!port){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

## Send and Recieve the response
req = http_get(item:string("/admin/index.jsp"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if('>ActiveMQ<' >< res)
{
  ##Construct attack request
  randam_value = rand();
  req = http_get(item:string("/admin/createDestination.action?",
                             "JMSDestinationType=queue&JMSDestination=",
                             "OpenVAS-XSS-Test-", randam_value), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Send and Recieve the response
  req = http_get(item:string("/admin/queues.jsp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  verify_string = string("OpenVAS-XSS-Test-", randam_value);
  ## Confirm exploit worked by checking the response
  if(verify_string >< res)
  {
    security_hole(port);
    exit(0);
  }
}
