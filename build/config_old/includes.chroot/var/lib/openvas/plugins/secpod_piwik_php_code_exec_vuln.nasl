###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_piwik_php_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Piwik PHP Code Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the remote attackers execute malicious PHP
  code to compromise the remote machine running the vulnerable application.
  Impact Level: Application";
tag_affected = "Open Flash Chart version 2 Beta 1 through 2.x
  Piwik version 0.2.35 through 0.4.3 on all platforms.";
tag_insight = "This flaw is due to improper validatin of data passed into 'name' and
  'HTTP_RAW_POST_DATA' parameters in ofc_upload_image.php which can be exploited
  to create php files containing malicious php code.";
tag_solution = "Upgrade Piwik to 0.4.4 or higher version,
  http://piwik.org/ and for Open Flash Chart,
  No solution or patch is available as of Decemeber 29th, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://teethgrinder.co.uk/open-flash-chart/";
tag_summary = "This host is running Piwik and is prone to PHP Code Execution
  vulnerability.";

if(description)
{
  script_id(900992);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4140");
  script_bugtraq_id(37314);
  script_name("Piwik PHP Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37078");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/12/14/1");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0910-exploits/piwik-upload.txt");

  script_description(desc);
  script_summary("Check for PHP file creation in Piwik");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

piwikPort = get_http_port(default:80);
if(!piwikPort){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/piwik054", "/analytics", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/index.php"), port:piwikPort);
  rcvRes = http_send_recv(port:piwikPort, data:sndReq);

  if("Piwik" >< rcvRes && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    request = http_get(item:string(dir+"/libs/open-flash-chart/php-ofc-library"+
                     "/ofc_upload_image.php?name=openvas.php"), port:piwikPort);
    response = http_send_recv(port:piwikPort, data:request);

    if("openvas.php" >< response && "tmp-upload-images" >< response &&
        egrep(pattern:"^HTTP/.* 200 OK", string:response))
    {
      security_hole(piwikPort);
      exit(0);
    }
  }
}
