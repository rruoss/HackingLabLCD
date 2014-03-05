###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_koha_opac_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Koha Library Software OPAC Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Koha Library Software versions 3.4.1 and prior.";
tag_insight = "The flaws are due to improper validation of user-supplied input in
  'bib_list' parameter to opac-downloadcart.pl, 'biblionumber' parameter to
  opac-serial-issues.pl, opac-addbybiblionumber.pl, opac-review.pl and
  'shelfid' parameter to opac-sendshelf.pl and opac-downloadshelf.pl.";
tag_solution = "Upgrade to Koha Library Software version 3.4.2 or later,
  For updates refer to http://koha-community.org/";
tag_summary = "The host is running Koha Library Software and is prone to multiple
  cross-site scripting vulnerabilities.";

if(description)
{
  script_id(902640);
  script_version("$Revision: 13 $");
  script_bugtraq_id(48895);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-30 11:26:06 +0530 (Wed, 30 Nov 2011)");
  script_name("Koha Library Software OPAC Multiple Cross Site Scripting Vulnerabilities");
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


  script_description(desc);
  script_summary("Check if Koha Library Software is vulnerable to XSS");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45435/");
  script_xref(name : "URL" , value : "http://koha-community.org/koha-3-4-2/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-05");
  script_xref(name : "URL" , value : "http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=6518");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103440/PT-2011-05.txt");
  script_xref(name : "URL" , value : "http://osvdb.org/vendor/118855-koha-library-software-community/1");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP port
port = get_http_port(default:80);

## Check port state
if(!get_port_state(port)) {
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/", "/koha", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: dir + "/opac-main.pl", port:port);
  res = http_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if("koha" >< res && "Library" >< res)
  {
    ## Construct the attack request
    url = string(dir, '/koha/opac-review.pl?biblionumber="<script>alert' +
                      '(document.cookie)</script>');

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"<script>alert" +
                       "\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
