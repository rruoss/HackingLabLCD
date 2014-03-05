###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_web_script_exec_vuln_jun09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Opera Web Script Execution Vulnerabilities - June09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary web script
  and spoof an arbitrary https site by letting a browser obtain a valid
  certificate.
  Impact Level: Application";
tag_affected = "Opera version prior to 9.25 on Windows.";
tag_insight = "- Error in processing a '3xx' HTTP CONNECT response before a successful SSL
    handshake, which can be exploited by modifying the CONNECT response
    to specify a 302 redirect to an arbitrary https web site.
  - Error exists while the HTTP Host header to determine the context of a
    document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
    which can be exploited by modifying this CONNECT response, aka an
    'SSL tampering' attack.
  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
    returned by a proxy server, which can be exploited by sending the browser a
    crafted 502 response page upon a subsequent request.
  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'";
tag_summary = "This host has Opera browser installed and is prone to Web Script
  Execution vulnerabilities.";

desc1 = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;
desc2 = "
  *****
  Note: Vulnerability is related to CVE-2009-2070 and CVE-2009-2067
  *****

  Overview: This host has Opera browser installed and is prone to Web Script
  Execution vulnerabilities.

  Vulnerability Insight:
  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
    returned by a proxy server, which can be exploited by sending the browser a
    crafted 502 response page upon a subsequent request.
  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'

  Impact:
  Successful exploitation will allow attacker to execute arbitrary web script
  and spoof an arbitrary https site by letting a browser obtain a valid
  certificate.

  Affected Software/OS:
  Opera version 9.64 and prior on Windows.";

desc_solution = "Upgarde to Opera Version 10 or later,
  For updates refer to http://www.opera.com/download/";

if(description)
{
  script_xref(name : "URL" , value : "http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name : "URL" , value : "http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_id(900367);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Opera Web Script Execution Vulnerabilities - June09 (Win)");
  script_description(desc1);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

# Check for Opera version < 9.25
if(version_is_less(version:operaVer, test_version:"9.25")){
  security_hole(data:string(desc1, desc_solution));
}
# Check for Opera version 9.25 <= 9.64
else if(version_in_range(version:operaVer, test_version:"9.25",
                         test_version2:"9.64")){
  security_hole(data:string(desc2, desc_solution));
}
