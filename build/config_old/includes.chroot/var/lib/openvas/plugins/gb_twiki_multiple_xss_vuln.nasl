###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TWiki 'newtopic' Parameter And SlideShowPlugin XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "TWiki version prior to 5.1.0";
tag_insight = "Multiple flaws are due to input validation error in,
  - 'newtopic' parameter in bin/view/Main/Jump (when 'template' is set to
    'WebCreateNewTopic')
  - 'lib/TWiki/Plugins/SlideShowPlugin/SlideShow.pm' in the 'SlideShowPlugin'
    pages containing a slideshow presentation.";
tag_solution = "upgrade to TWiki 5.1.0 or later,
  For updates refer to http://twiki.org/cgi-bin/view/Codev/DownloadTWiki";
tag_summary = "The host is running TWiki and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(802335);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_cve_id("CVE-2011-3010");
  script_bugtraq_id(49746);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("TWiki 'newtopic' Parameter And SlideShowPlugin XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/75673");
  script_xref(name : "URL" , value : "http://osvdb.org/75674");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46123");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1026091");
  script_xref(name : "URL" , value : "http://www.mavitunasecurity.com/xss-vulnerability-in-twiki5/");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check for XSS vulnerability in TWiki");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
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

## Check for default port
twikiPort = get_http_port(default:80);
if(!twikiPort){
  twikiPort = 80;
}

## Check port state
if(!get_port_state(twikiPort)){
  exit(0);
}

## Get Twiki Installed Location
if(!dir = get_dir_from_kb(port:twikiPort, app:"TWiki")){
  exit(0);
}

## Construct attack Request
url = string(dir,"/bin/view/Main/Jump?create=on&amp;newtopic='" +
            '"--></style></script><script>alert(document.cookie)</script>' +
            '&amp;template=WebCreateNewTopic&amp;topicparent=3');

##Confirm the exploit
if(http_vuln_check(port:twikiPort, url:url,pattern:"</style></script>" +
          "<script>alert\(document.cookie\)</script>",extra_check:"TWiki"))
{
  security_warning(twikiPort);
  exit(0);
}
