###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_podcast_generator_41473.nasl 14 2013-10-27 12:33:37Z jan $
#
# Podcast Generator 'download.php' Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Podcast Generator is prone to a directory-traversal vulnerability
because it fails to sufficiently validate user-supplied input data.

Exploiting the issue can allow an attacker to obtain sensitive
information that may aid in further attacks.

Podcast Generator 1.3 running on Windows is vulnerable; other versions
may also be affected.";


if (description)
{
 script_id(100709);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-09 12:33:08 +0200 (Fri, 09 Jul 2010)");
 script_bugtraq_id(41473);

 script_name("Podcast Generator 'download.php' Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41473");
 script_xref(name : "URL" , value : "http://www.scribd.com/doc/28080332/Podcast-Generator-1-3-Arbitrary-File-Download-Windows");
 script_xref(name : "URL" , value : "http://podcastgen.sourceforge.net/download.php?lang=en");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Podcast Generator version is <= 1.3");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","podcast_generator_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (host_runs("windows") == "no") exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"podcast_generator")) {

  if(version_is_less_equal(version: vers, test_version: "1.3")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
