###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sgx-sp_final_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "SGX-SP Final version 10.0 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input passed to
  shop.cgi, which allows attackers to execute arbitrary HTML and script code
  in a user's browser session in context of an affected site.";
tag_solution = "Upgrade to SGX-SP Final version 11.0 or later,
  For updates refer to http://wb-i.net/";
tag_summary = "This host is running SGX-SP Final and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(902532);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2010-3926");
  script_bugtraq_id(45752);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SGX-SP Final 'shop.cgi' Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70410");
  script_xref(name : "URL" , value : "http://wb-i.net/soft1.HTML#spf");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42857");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64593");

  script_description(desc);
  script_summary("Check for the version of SGX-SP Final");
  script_category(ACT_GATHER_INFO);
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/SPF", "/shop", "/mall", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir, "/shop.cgi"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application and Get version
  ver = eregmatch(pattern:'SGX-SPF Ver([0-9.]+)', string:res);
  if(ver[1])
  {
    ## Check for SGX-SP Final version 10.0 and prior
    if(version_is_less(version:ver[1], test_version:"11.00"))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
