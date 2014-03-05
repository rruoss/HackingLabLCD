# OpenVAS Vulnerability Test
# $Id: imp_content_type_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IMP Content-Type XSS Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
tag_summary = "The remote server is running at least one instance of IMP whose version
number is between 2.0 and 3.2.3 inclusive.  Such versions are vulnerable
to a cross-scripting attack whereby an attacker may be able to cause a
victim to unknowingly run arbitrary Javascript code simply by reading a
MIME message with a specially crafted Content-Type header. 

For information about the vulnerability, including exploits, see :

  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

Note : OpenVAS has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there; it has
not attempted to actually exploit the vulnerability.";

tag_solution = "Upgrade to IMP version 3.2.4 or later.";

if (description) {
  script_id(12263);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10501);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

  script_cve_id("CVE-2004-0584");
  script_xref(name:"GLSA", value:"GLSA-200406-11");
 
  name = "IMP Content-Type XSS Vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);

  summary = "Checks for Content-Type XSS Vulnerability in IMP";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Content-Type XSS vulnerability in IMP on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^(2\.|3\.(0|1|2|2\.[1-3]))$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
