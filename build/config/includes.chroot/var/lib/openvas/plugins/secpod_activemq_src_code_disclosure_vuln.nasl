###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_activemq_src_code_disclosure_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache ActiveMQ Source Code Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_solution = "Upgrade to the latest version of ActiveMQ 5.4.0 SNAPSHOT or later,
  For updates refer to http://activemq.apache.org/download.html

  Workaround:
  Apply workaround as in the link,
  https://issues.apache.org/activemq/browse/AMQ-2700";

tag_impact = "Successful exploitation allows an attacker to view the source code of
  a visited page which can be used for further attacks.
  Impact Level: Application";
tag_affected = "Apache ActiveMQ 5.3.1 and prior.";
tag_insight = "The flaw is caused by improper validation of URL. Adding '//' after the
  port in an URL causes it to disclose the JSP page source.";
tag_summary = "This host is running Apache ActiveMQ and is prone to source code
  information disclosure vulnerability.";

if(description)
{
  script_id(901110);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1587");
 script_bugtraq_id(39636);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache ActiveMQ Source Code Information Disclosure Vulnerability");
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

  script_xref(name : "URL" , value : "https://issues.apache.org/activemq/browse/AMQ-2700");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510896");

  script_description(desc);
  script_summary("Check if ActiveMQ is vulnerable to Source Code Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8161);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

## Send and Recieve the response
req = http_get(item:string("/admin/index.jsp"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if('>ActiveMQ<' >< res)
{
  ##Construct attack request
  req = http_get(item:string("//admin/queues.jsp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(('${sessionScope["secret"]}' >< res)){
    security_warning(port);
  }
}
