# OpenVAS Vulnerability Test
# $Id: cups_multiple_vulnerabilities.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CUPS < 1.1.23 Multiple Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is running a CUPS server whose version number is
between 1.0.4 and 1.1.22 inclusive.  Such versions are prone to
multiple vulnerabilities :

  - The is_path_absolute function in scheduler/client.c for the 
    daemon in CUPS allows remote attackers to cause a denial
    of service (CPU consumption by tight loop) via a '..\..'
    URL in an HTTP request.

  - A remotely exploitable buffer overflow in the 'hpgltops'
    filter that enable specially crafted HPGL files can 
    execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing 
    his or her password until a temporary copy of the new 
    password file is cleaned up ('lppasswd' flaw).

  - A local user may be able to add arbitrary content to the 
    password file by closing the stderr file descriptor 
    while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS 
    password file, thereby denying service to valid clients 
    using digest authentication. (lppasswd flaw).

  - The application applys ACLs to incoming print jobs in a 
    case-sensitive fashion. Thus, an attacker can bypass 
    restrictions by changing the case in printer names when 
    submitting jobs. [Fixed in 1.1.21.]

***** OpenVAS has determined the vulnerability exists simply
***** by looking at the version number of CUPS installed on
***** the remote host.";

tag_solution = "Upgrade to CUPS 1.1.23 or later.";

if (description) {
  script_id(16141);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

  script_cve_id("CVE-2004-1267","CVE-2004-1268","CVE-2004-1269","CVE-2004-1270","CVE-2005-2874");
  script_bugtraq_id(11968, 12004, 12005, 12007, 12200, 14265);
  script_xref(name:"OSVDB", value:"12439");
  script_xref(name:"OSVDB", value:"12453");
  script_xref(name:"OSVDB", value:"12454");
  script_xref(name:"FLSA", value:"FEDORA-2004-908");
  script_xref(name:"FLSA", value:"FEDORA-2004-559");
  script_xref(name:"FLSA", value:"FEDORA-2004-560");
  script_xref(name:"GLSA", value:"GLSA-200412-25");

  name = "CUPS < 1.1.23 Multiple Vulnerabilities";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);

  summary = "Checks version of CUPS";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  family = "Gain a shell remotely";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl", "http_version.nasl");
  script_require_keys("www/cups");
  script_require_ports("Services/www", 631);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L700");
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L1024");
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L1023");
  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L1042");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:631);
if (!port) exit(0);

# Check as long as it corresponds to a CUPS server.
banner = get_http_banner(port:port);
banner = strstr(banner, "Server: CUPS");
if (banner != NULL) {

  # Get the version number, if possible.
  banner = banner - strstr(banner, string("\n"));
  pat = "^Server: CUPS/?(.*)$";
  ver = eregmatch(string:banner, pattern:pat);
  if (isnull(ver)) exit(0);

  ver = chomp(ver[1]);
  if (ver =~ "^1\.(0(\.)?|1\.(1|2[0-2]))") 
    security_hole(port:port);
}
