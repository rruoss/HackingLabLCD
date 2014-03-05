# OpenVAS Vulnerability Test
# $Id: simple_form_mail_relaying_via_subject_tags.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Simple Form Mail Relaying via Subject Tags Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
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
tag_summary = "The target is running at least one instance of Simple Form which fails
to remove newlines from variables used to construct message headers. 
A remote attacker can exploit this flaw to add to the list of
recipients, enabling him to use Simple Form on the target as a proxy
for sending abusive mail or spam.";

tag_solution = "Upgrade to Simple Form 2.3 or later.";

if (description) {
  script_id(14713);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  name = "Simple Form Mail Relaying via Subject Tags Vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);

  summary = "Checks for Mail Relaying via Subject Tags Vulnerability in Simple Form";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://worldcommunity.com/opensource/utilities/simple_form.html");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for mail relaying via subject tags vulnerability in Simple Form on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check for the form in each of the CGI dirs.
foreach dir (cgi_dirs()) { 
  if (  is_cgi_installed_ka(item:dir + "/s_form.cgi", port:port) ) 
  {
  url = string(dir, "/s_form.cgi");
  if (debug_level) display("debug: checking ", url, "...\n");

  # Exploit the form and *preview* the message to determine if the
  # vulnerability exists. Note: this doesn't actually inject a 
  # message but should give us an idea if it is vulnerable.
  #
  # nb: preview mode won't actually show the modified subject so we
  #     check whether we have a vulnerable version by trying to set
  #     preview_response_title -- if we can, we're running a 
  #     non-vulnerable version.
  boundary = "bound";
  req = string(
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", host, "\r\n",
    "Referer: http://", host, "/\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
     boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_response_title"', "\r\n",
    "\r\n",
    "A Response\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_return_url"', "\r\n",
    "\r\n",
    "http://", host, "/\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_return_url_title"', "\r\n",
    "\r\n",
    "Home\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="required_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_email_subject"', "\r\n",
    "\r\n",
    "OpenVAS Plugin Test:!:xtra_recipients:!:\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="subject_tag_field"', "\r\n",
    "\r\n",
    "xtra_recipients\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="xtra_recipients"', "\r\n",
    "\r\n",
    "\nCC: victim@example.com\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="msg"', "\r\n",
    "\r\n",
    "This is a mail relaying test.\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="preview_data"', "\r\n",
    "\r\n",
    "yes\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="preview_response_title"', "\r\n",
    "\r\n",
    "OpenVAS Plugin Preview",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  if (debug_level) display("debug: sending =>>", req, "<<\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  if (debug_level) display("debug: received =>>", res, "<<\n");

  # Look at the preview and see whether we get *our* preview_response_title.
  if (
    res >< "OpenVAS Plugin Test:!:xtra_recipients:!:" && 
    res >!< "OpenVAS Plugin Preview"
  ) {
    security_hole(port);
    exit(0);
  }
 }
}
