###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_annuaire_php_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Annuaire PHP 'sites_inscription.php' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of a vulnerable
  site.
  Impact Level: Application";
tag_affected = "Annuaire PHP";
tag_insight = "The flaw is due to an input passed via the 'url' and 'nom' parameters to
  'sites_inscription.php' page is not properly verified before it is returned
  to the user.";
tag_solution = "No solution or patch is available as of 24th, January 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.annuairephp.com/";
tag_summary = "This host is running Annuaire PHP and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(902787);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-24 18:49:12 +0530 (Tue, 24 Jan 2012)");
  script_name("Annuaire PHP 'sites_inscription.php' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72407");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/108719/annuaire-xss.txt");

  script_description(desc);
  script_summary("Check if Annuaire PHP is prone to XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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
if(!get_port_state(port)) {
  exit(0);
}

foreach dir (make_list("/", "/annuaire", "/Annuaire", cgi_dirs()))
{
  sndReq = http_get(item:string(dir,"/referencement/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(">Annuaire" >< rcvRes || "annuaire" >< rcvRes)
  {
    ## Construct attack
    url = string (dir + "/referencement/sites_inscription.php?nom=xss&url=" +
                        "><script>alert(document.cookie)</script>");

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document." +
                                                   "cookie\)</script>"))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
