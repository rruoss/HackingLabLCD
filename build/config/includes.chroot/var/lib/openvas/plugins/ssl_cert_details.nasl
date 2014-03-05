# OpenVAS
# $Id: ssl_cert_details.nasl 45 2013-11-05 15:43:35Z mime $
# Description: Collect details about SSL certifciates.
#
# Authors:
# Werner Koch <wk@gnupg.org>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

include("revisions-lib.inc");
tag_summary = "This script collects and reports the details of all SSL certificates.

This data will be used by other tests to verify server certificates.
At least OpenVAS Libraries 6.0 are required.";

##
# This is a list of KB entries created by this script.  To avoid
# storing certificate details over and over again we use the SHA-256
# fingerprint of a certificate as the unique identifier.  The reason
# we do not use SHA-1 here is that we expect to see SHA-1 collisions
# for valid X.509 certificates in the not too far future. OpenVAS
# should be able to single those attacks out.  It is easier to use
# SHA-256 right now, than to switch to it later.
#
# The following keys are all prefixed with:
#   HostDetails/Cert/<sha-256-fingerprint>
#
# /type      => The type of the certificate; always: "X.509"
# /serial    => Serial number as hex string
# /issuer    => Issuer as rfc2253 string
# /subject   => Subject as rfc2253 string
# /subject/N => Subject alt names with N counting from 1.  The format
#               is either an rfc2253 string as used above, an rfc2822
#               mailbox name indicated by the first character being a
#               left angle bracket or an S-expression in advanced
#               format for all other types of subjectAltnames which is
#               indicated by an opening parentheses.
# /notBefore => The activation time in UTC in ISO time format.
# /notAfter  => The expiration time in UTC in ISO time format.
# /fprSHA1   => The SHA-1 fingerprint
# /image     => The entire certificate as a base64 encoded string.
# /hostnames => All hostnames (CN from subject and all dns-name
#               altSubjectNames) as a comma delimited string.
#
# These entries give detailed information about a certificate.  A
# server may return several certificates: The actual server
# certificates may be followed by other certificates which make up
# the chain.  Futher the server may return different certificates
# depending on the SNI.  To collect these details we use these entries:
#
# HostDetails/SSLInfo/<port>        <fingerprint>, <fingerprint>, ...
# HostDetails/SSLInfo/<port>/<host> <fingerprint>, <fingerprint>, ...
#
# If there is an error with one of the certificates, the fingerprint
# is replaced by the string "[ERROR]".  NVTs evaluating the
# fingerprints should thus check whether first character of each
# fingerprint is a '['.
#
# The preliminary report format is:
#
# <host>
#   <detail>
#     <name>Cert:SHA256_HEXSTRING</name>
#     <value>x509:BASE64_STRING</value>
#   </detail>
#   <detail>
#     <name>SSLDetails:SHA256_HEXSTRING</name>
#     <value>serial:HEX_STRING|hostnames:HOSTS|notBefore:UTC_ISO|notAfter:UTC_ISO</value>
#   </detail>
#   <detail>
#     <name>SSLInfo</name>
#     <value>PORT:HOSTNAME:FINGERPRINT_LIST</value>
#   </detail>
# </host>
#
##


if(description)
{
  script_id(103692);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 45 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-05 16:43:35 +0100 (Di, 05. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-04-09 14:14:14 +0200 (Tue, 09 Apr 2013)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL Certificate Details");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Collects SSL certificate details.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ssl_ciphers.nasl");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


# Check that cert_open is available (since 6.0).  However, we also
# need to check that a decent version of cert_open is available, thus
# the extra check for version 7.  The required code is available in
# trunk since 2013-04-10.
if (!defined_func("cert_open")
    || revcomp(a: OPENVAS_VERSION, b: "7") < 0) {
  exit (0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
# For report_host_detail_single()
include("host_details.inc");


function read_and_parse_certs(cert, port) {
  local_var prefix, certobj, idx, tmp, hostnames;

  certobj = cert_open(cert);
  if (!certobj) {
    set_kb_item(name:("HostDetails/SSLInfo/" + port),
                value:"[ERROR]");
    log_message(data:string("The SSL certificate of the",
                            " remote service cannot be parsed!"),
                port:port);
    exit(0);
  }

  if (log_verbosity > 1) {
    debug_print("SSL certificate on port ", port, ":\n");
    debug_print("serial ..........: ", cert_query(certobj,"serial"),"\n");
    debug_print("issuer ..........: ", cert_query(certobj,"issuer"),"\n");
    debug_print("subject .........: ", cert_query(certobj,"subject"),"\n");
    for (idx=1; (tmp = cert_query(certobj, "subject", idx:idx)); idx++)
      debug_print("altSubjectName[", idx, "]: ", tmp, "\n");
    debug_print("notBefore .......: ", cert_query(certobj,"not-before"),"\n");
    debug_print("notAfter ........: ", cert_query(certobj,"not-after"),"\n");
    debug_print("fpr (SHA-1) .....: ", cert_query(certobj,"fpr-sha-1"),"\n");
    debug_print("fpr (SHA-256) ...: ", cert_query(certobj,"fpr-sha-256"),"\n");
    debug_print("hostnames .......: ", cert_query(certobj,"hostnames"),"\n");
  }

  fpr = cert_query(certobj, "fpr-sha-256");

  # Insert the certificiate details into the list of certificates if
  # not already done.  Because we use the fingerprint we know that all
  # KB items of the certificate will be identical (unless a script was
  # changed during a run).
  prefix = "HostDetails/Cert/" + fpr;
  if (isnull(get_kb_item(prefix + "/type"))) {
    set_kb_item(name:prefix + "/type", value:"X.509");
    set_kb_item(name:prefix + "/serial",
                value:cert_query(certobj, "serial"));
    set_kb_item(name:prefix + "/issuer",
                value:cert_query(certobj, "issuer"));
    set_kb_item(name:prefix + "/subject",
                value:cert_query(certobj, "subject"));
    for (idx=1; (tmp = cert_query(certobj, "subject", idx:idx)); idx++)
      set_kb_item(name:prefix + "/subject/" + idx, value:tmp);
    set_kb_item(name:prefix + "/notBefore",
                value:cert_query(certobj, "not-before"));
    set_kb_item(name:prefix + "/notAfter",
                value:cert_query(certobj, "not-after"));
    set_kb_item(name:prefix + "/fprSHA1",
                value:cert_query(certobj, "fpr-sha-1"));
    set_kb_item(name:prefix + "/image",
                value:base64(str:cert_query(certobj, "image")));

    hostnames = cert_query(certobj, "hostnames");
    if (!isnull(hostnames)) {
      tmp = "";
      foreach item(hostnames) {
        if (tmp != "")
          tmp = tmp + ",";
        tmp = tmp + item;
      }
      set_kb_item(name:prefix + "/hostnames", value:tmp);
    }
  }

  # Register the certificate and the port
  prefix = "HostDetails/SSLInfo/";

  # FIXME: Extend get_server_cert and return an array of certificates.

  # FIXME: What to do if the server returns random certificates?

  set_kb_item(name:prefix + port, value:fpr);

  # FIXME: We need a list of virtual hostnames to request
  # certificates using the SNI.

  cert_close(certobj);
}

# Iterate over the host details keys Cert and SSL and report them.
function report_ssl_cert_details() {
  local_var certs, key, fpr, tmp, ssls, oid, description;

  oid = "1.3.6.1.4.1.25623.1.0.103692";

  certs = get_kb_list("HostDetails/Cert/*/type");
  if(certs) {
    foreach key(keys(certs)) {
      local_var issuer, serial, not_before, not_after, image;

      tmp = split(key, sep:"/", keep:FALSE);
      fpr = tmp[2];
      issuer = get_kb_item("HostDetails/Cert/" + fpr + "/issuer");
      serial = get_kb_item("HostDetails/Cert/" + fpr + "/serial");
      not_before = get_kb_item("HostDetails/Cert/" + fpr + "/notBefore");
      not_after = get_kb_item("HostDetails/Cert/" + fpr + "/notAfter");
      image = get_kb_item("HostDetails/Cert/" + fpr + "/image");

      tmp = 'issuer:' + issuer + '|serial:' + serial + '|notBefore:'
            + not_before + '|notAfter:' + not_after;

      report_host_detail_single(name:('Cert:'+fpr), value:('x509:'+image),
                                nvt:oid, desc:"SSL Certificate");

      report_host_detail_single(name:('SSLDetails:'+fpr), value:tmp,
                                nvt:oid, desc:"SSL Certificate Details");
    }
  }  

  ssls = get_kb_list("HostDetails/SSLInfo/*");
  if(ssls) {
    foreach key(keys(ssls)) {
      tmp = split(key, sep:"/", keep:FALSE);
      port = tmp[2];
      host = tmp[3];
      tmp = port + ':' + host + ':' + get_kb_item(key);

      report_host_detail_single(name:"SSLInfo", value:tmp, nvt:oid,
                                desc:"SSL Certificate Information");
     }
  }  
}


#
# main
#
portlist = get_kb_list("TCP/PORTS");
foreach port(portlist) {
  cert = get_server_cert(port:port, encoding:"der");
  if (cert) {
    read_and_parse_certs(cert:cert, port:port);
  }
}
report_ssl_cert_details();

# Local Variables:
# c-basic-offset: 2
# End:
