# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

package TasksConsole::Prover::Website;
use parent 'OpenConsole::Session::Task';

use OpenConsole::Util  qw(get_page is_valid_zulu is_valid_token timestamp);

use Log::Report        'open-console-tasks';

use Encode             qw(encode decode);
use HTTP::Status       qw(is_redirect is_client_error is_error is_success);
use JSON               ();
use List::Util         qw(first);
use Net::DNS::Resolver ();
use Net::DNS::SEC      ();
use Net::LibIDN2       qw(:all);
use Scalar::Util       qw(blessed);
use Time::HiRes        ();
use URI                ();
use URI::Escape        qw(uri_escape uri_unescape);
use URI::Split         qw(uri_split uri_join);
use XML::LibXML        ();

my $resolver;
BEGIN {
	$resolver = Net::DNS::Resolver->new(dnssec => 1);
}

# From libidn2 version 0.3.6,
# "transitional" is IDNA2003->IDNA2008 spec, see https://unicode.org/reports/tr46/

my %idn2_errors = (
	# /usr/include/idn2.h comment 'idn2_rc' lines 228-256
	# Impossible errors do not get a translation.
#	&IDN2_OK				=> 'Successful return.',
#	&IDN2_MALLOC			=> 'Memory allocation error.',
#	&IDN2_NO_CODESET		=> 'Could not determine locale string encoding format.',
#	&IDN2_ICONV_FAIL		=> 'Could not transcode locale string to UTF-8.',
	&IDN2_ENCODING_ERROR	=> 'Unicode data encoding error.',
	&IDN2_NFC				=> 'Error normalizing string.',
	&IDN2_PUNYCODE_BAD_INPUT		=> 'Punycode invalid input.',
	&IDN2_PUNYCODE_BIG_OUTPUT		=> 'Punycode output buffer too small.',
	&IDN2_PUNYCODE_OVERFLOW	=> 'Punycode conversion would overflow.',
	&IDN2_TOO_BIG_DOMAIN	=> 'Domain name longer than 255 characters.',
	&IDN2_TOO_BIG_LABEL		=> 'Domain label longer than 63 characters.',
#	&IDN2_INVALID_ALABEL	=> 'Input A-label is not valid.',
#	&IDN2_UALABEL_MISMATCH	=> 'Input A-label and U-label does not match.',
#	&IDN2_INVALID_FLAGS		=> 'Invalid combination of flags.',
#	&IDN2_NOT_NFC			=> 'String is not NFC.',
	&IDN2_2HYPHEN			=> 'String has forbidden two hyphens.',
	&IDN2_HYPHEN_STARTEND	=> 'String has forbidden starting/ending hyphen.',
	&IDN2_LEADING_COMBINING	=> 'String has forbidden leading combining character.',
	&IDN2_DISALLOWED		=> 'String has disallowed character.',
	&IDN2_CONTEXTJ			=> 'String has forbidden context-j character.',
	&IDN2_CONTEXTJ_NO_RULE	=> 'String has context-j character with no rull.',
	&IDN2_CONTEXTO			=> 'String has forbidden context-o character.',
	&IDN2_CONTEXTO_NO_RULE	=> 'String has context-o character with no rull.',
	&IDN2_UNASSIGNED		=> 'String has forbidden unassigned character.',
	&IDN2_BIDI				=> 'String has forbidden bi-directional properties.',
	&IDN2_DOT_IN_LABEL		=> 'Label has forbidden dot (TR46).',
	&IDN2_INVALID_TRANSITIONAL		=> 'Label has character forbidden in transitional mode (TR46).',
#	&IDN2_INVALID_NONTRANSITIONAL	=> 'Label has character forbidden in non-transitional mode (TR46).',
	&IDN2_ALABEL_ROUNDTRIP_FAILED	=> 'ALabel -> Ulabel -> ALabel result differs from input.',
);

# Punycode="limited ASCII character subset used for Internet hostnames"
# See https://en.wikipedia.org/wiki/Punycode
sub _domainToPunycode($$)
{	my ($self, $field, $domain) = @_;
	my $rc     = IDN2_OK;
	my $puny   = idn2_lookup_u8 $domain, IDN2_NFC_INPUT|IDN2_ALABEL_ROUNDTRIP|IDN2_TRANSITIONAL, $rc;

	unless($rc == IDN2_OK)
	{	$self->_trace($idn2_errors{$rc} || 'idn2 error $rc.');
		$self->addError($field, __"Invalid hostname.");
		return undef;
	}

	$puny;
}

sub _punycodeToDomain($$)
{	my ($self, $field, $puny) = @_;
	my $rc     = IDN2_OK;
	my $domain = decode 'UTF-8', (idn2_to_unicode_88 $puny, 0, $rc);

	unless($rc == IDN2_OK)
	{	$self->_trace($idn2_errors{$rc} || 'idn2 error $rc.');
		$self->addError($field, __"Invalid hostname as punycode.");
		return undef;
	}

	$domain;
}

sub _normalizeWebsiteURL($$%)
{	my ($self, $field, $url, %args) = @_;

	if($url !~ m,://,)
	{	# parsing does not work without this check
		$self->_trace('Set default scheme to https.');
		$url = "https://$url";
	}

	my ($scheme, $auth, $path, $query, $frag) = uri_split $url;

	if($scheme ne lc($scheme))
	{	$self->_trace('Normalizing to lower-case scheme name.');
		$scheme = lc $scheme;
	}

	if($auth =~ /\@/)
	{	$self->addError($field => __x"Username or password for website is deprecated, not accepted.");
		return undef;
	}

	my ($host, $port) = $auth =~ m!^([^:]+)(?:[:](\d+))?$!;
	unless(defined $host)
	{	$self->addError($field => __x"No valid hostname:port in URI.");
		return undef;
	}

	### SCHEME

	if($scheme eq 'http')
	{	if(defined $port && $port==80)
		{	$self->_trace('Removed default portnumber 80 for http.');
			undef $port;
		}
	}
	elsif($scheme eq 'https')
	{	if(defined $port && $port==443)
		{	$self->_trace('Removed default portnumber 443 for http.');
			undef $port;
		}
	}
	else
	{	$self->addError($field => __"Unsupported website protocol.");
		return undef;
	}

	### HOST

	my $host_unesc = $host =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ger;
	if($host ne $host_unesc)
	{	$self->_trace('Unescaped uri-encoding in host name.');
		$host = $host_unesc;
	}

	if($host =~ s/\.$//)
	{	$self->_trace('Removed superfluous trailing dot in host name.');
	}

	if($host =~ m!^[0-9.:]+$!)
	{	$self->addError($field => __"IP-address for hostname not accepted.");
		return undef;
	}

	($host, my $puny) = $host =~ /xn--/
	  ? ($self->_punycodeToDomain($field, $host), $host)
	  : ($host, $self->_domainToPunycode($field, $host));

	foreach my $label (split /\./, $puny)
	{	# Validity of chars not checked by LibIDN
		if($label =~ /([^a-zA-Z0-9-])/)
		{	$self->addError($field => __x"Illegal ASCII character '{c}' used in host name.", c => $1);
			return undef;
		}
	}

	($auth, my $auth_printable) = defined $port ? ("$puny:$port", "$host:$port") : ($puny, $host);

	### PATH

	my $path_printable = '';

	if($path eq '/')
	{	$self->_trace('Removed path to root.');
		$path = '';
	}
	elsif($path =~ m,^/\~([^/]+)/?$,)
	{	my $user = $1;
		my $user_decoded = uri_unescape $user;
		my $user_recoded = uri_escape $user_decoded;
		$user eq $user_recoded or $self->_trace('Normalized user-path characters.');
		$path = "/~$user_recoded/";
		$path_printable  = decode 'UTF-8', $user_decoded;
	}
	elsif(length $path)
	{	$self->addError($field => __"Only user-path can be used in a website.");
		return undef;
	}

	### QUERY & FRAGMENT

	if(defined $query && length $query)
	{	$self->_trace('Query as part of website not accepted. Ignored.');
		undef $query;
	}

	if(defined $frag && length $frag)
	{	$self->_trace('Fragment as part of website is not correct. Ignored.');
		undef $frag;
	}

	my $normalized_url = uri_join $scheme, $auth, $path;
	$url eq $normalized_url
		or $self->_trace("Continuing with '$normalized_url'.");

	$self->results(+{
		url_normalized   => $normalized_url,
		url_printable    => (uri_join $scheme, $auth_printable, $path_printable),
		host_puny        => $puny,
	});
}

sub _getRR($$$$)
{	my ($self, $field, $host, $rr_type, $sigs, $keys) = @_;

	my $packet = $resolver->send($host, $rr_type, 'IN');
	my @answer = $packet->answer;
	my @rr     = grep $_->type eq $rr_type, @answer;
	unless(@rr && @$keys)
	{	@$keys or $self->_trace("No DNSSEC records found for $rr_type.");
		return (NO_DNSSEC => \@rr);
	}

	my $rrsig  = first { $_->typecovered eq $rr_type } @$sigs;
	my ($status, $msg)
	 = ! $rrsig
	 ? (MISSING_DNSSEC_SIGNATURE => "DNSSEC signature missing for $rr_type records.")
	 : $rrsig->verify(\@rr, $keys)
	 ? (DNSSEC_SIGNED => "DNSSEC valid signature on $rr_type records.")
	 : (DNSSEC_INVALID_SIGNATURE => "DNSSEC signature on $rr_type records is invalid.");
 
	$self->addWarning($field => __"DNSSEC issues found.") if $status ne 'DNSSEC_SIGNED';
	$self->_trace($msg);

	($status, \@rr);
}

sub _verifyDNS($)
{	my ($self, $field) = @_;
	my $results = $self->results;
	my $host    = $results->{host_puny};
#warn "HOST=$host";

	my %check;
	$results->{dns_check} = \%check;

	my (@keys, @sigs, @cnames);

	while(@cnames < 10)
	{	#XXX Is this really the location for the keys?
		#XXX is the Resolver already doing these DNSSEC checks: will it crash on bad keys?
		@keys  = grep $_->type eq 'DNSKEY', $resolver->send($host, 'DNSKEY', 'IN')->answer;
		@sigs  = grep $_->type eq 'RRSIG',  $resolver->send($host, 'RRSIG', 'IN')->answer;

		my ($status, $rr_cname) = $self->_getRR($field, $host => 'CNAME', \@sigs, \@keys);
		last unless @$rr_cname;

		$host = $rr_cname->[0]->cname;
		push @cnames, +{ dnssec => $status, cname => $host };
		$self->_trace("CNAME redirection to $host");
	}
	if(@cnames >= 10)
	{	$self->addError($field, __"Too many CNAME redirections for host.");
		return undef;
	}
	$check{cname_chain} = \@cnames;

	($check{ipv4_dnssec}, my $rr_a) = $self->_getRR($field, $host => 'A', \@sigs, \@keys);
	$check{ipv4} = [ map $_->address, @$rr_a ];

	($check{ipv6_dnssec}, my $rr_a4) = $self->_getRR($field, $host => 'AAAA', \@sigs, \@keys);
	$check{ipv6} = [ map $_->address, @$rr_a4 ];
 
	unless(@$rr_a || @$rr_a4)
	{	$self->addError($field, __"The website address does not exist.");
		return undef;
	}

	\%check;
}

sub _getWebpage($)
{	my ($self, $field) = @_;
	my $results = $self->results;
	my $url     = $results->{url_normalized};

	my ($response, $check) = get_page $self, $url;
	$results->{site_check} = $check;

	my $code    = $response->code;
	if(is_client_error $code)
	{	$self->addError($field, __x"Internal error: unabled to check the website.  Please contact support.");
		return;
	}

	if(is_error $code)
	{	$self->addError($field, __x"Page {url} resulted in error {code}.  Please fix.", url => $url, code => $code);
		return;
	}

	if(is_redirect $code)
	{	my $to_rel = $response->header('Location');
		unless($to_rel)
		{	$self->addError($field, __x"Browser redirect without Location for {url}.", url => $url);
			return undef;
		}

		my $to_abs = URI->new_abs($to_rel, $url);
		$self->_trace("Redirected to $to_abs");
		$self->addError($field, __x"The url redirects to '{url}': not canonical.", url => $to_abs);
		return;
	}

	# See https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls
	# https://developers.google.com/search/docs/crawling-indexing/canonicalization-troubleshooting
	my $canonical;
	my @links   = $response->headers->header('Link');
	if($canonical = first { s/; rel="canonical".*// } @links)
	{	$canonical = $1 if $canonical =~ m!\<([^>]*)\>!;
		$self->_trace("Link canonical to '$canonical' in headers.");
	}

	unless(defined $canonical)
	{	my $content = $response->decoded_content;
		if($content =~ m!\<\s*link\s+rel=(['"]?)canonical\1\s+href=(?:["']([^"]{1,300})["']|(\S{1,300}))!is)
		{	$canonical = $2 // $3;
			$self->_trace("Link canonical to '$canonical' in html.");
		}
	}

	if($canonical)
	{	$check->{canonical} = $canonical;
		my $canon  = URI->new($canonical);
		my $website= URI->new($url);

    	my $rc     = IDN2_OK;
    	my $puny   = idn2_lookup_u8 $canon->host, IDN2_NFC_INPUT|IDN2_ALABEL_ROUNDTRIP|IDN2_TRANSITIONAL, $rc;

		if($puny eq $website->host && $canon->scheme eq $website->scheme && $canon->port==$website->port)
		{	$self->_trace("Canonical in the same website");
		}
		else
		{	my $short = $canon->scheme . "://$puny";
			$short .= ':' . $canon->port if $canon->port != $canon->default_port;
			$self->addError($field => __x"Canonical link in webpage points to different website {url}.", url => $short);
		}
	}
	else
	{	$self->_trace("No canonical name for the website found in the html.");
	}

	$check;
}

sub checkWebsite(%)
{	my ($self, %args) = @_;
	my $field = $args{field};
	my $url   = $args{website};

	$self->_trace("Checking field '$field' value '$url'");

	$self->_normalizeWebsiteURL($field, $url)
		or return undef;

	$self->_verifyDNS($field)
		or return undef;

	$self->_getWebpage($field);
	$self;
}

###

sub _getJSON($$)
{	my ($self, $field, $file) = @_;
	my $start     = timestamp;
	my ($response, $fetch) = get_page $self, $file;
	$fetch->{start} = $start;

	my $code      = $response->code;
	unless(is_success $code)
	{	$self->_trace("File could not be fetched, code $code");
		$self->addError($field, __x"Could not fetch the challenge file.");
		return ($fetch, undef);
	}

	# I don't care whether the server sees this a application/json

	my $json = try { JSON->new->decode($response->decoded_content) };
	if($@)
	{	my $err = "$@";
		(substr $err, 61) = '...' if length $err > 64;
		$self->_trace("The JSON is corrupt: $err");
		$self->addError($field, __x"The JSON in the file is corrupt.");
		return ($fetch, undef);
	}

	if(ref $json ne 'ARRAY')
	{	$self->_trace("JSON structure is an ".ref($json));
		$self->addError($field, __x"The JSON file does not contain an ARRAY of records.");
		return ($fetch, undef);
	}

	$self->_trace("The JSON looks healthy");
	($fetch, $json);
}

sub _validateChallenge($)
{	my ($self, $node) = @_;

	my $version = $node->{version};
	$version =~ m!^website (?:file|html) [0-9]{8}$! or return ();

	my $created = $node->{created} || '';
	unless(is_valid_zulu $created)
	{	$self->addError("Created timestamp corrupt.");
		return ();
	}

	my $challenge = $node->{challenge} || '';
	if(is_valid_token $challenge)
	{	$self->_trace("Found challenge created on $created.");
	}
	else
	{	$self->addError("Invalid challenge which was created on $created");
		return ();
	}
		
	# Do only return validated values to the caller!
	+{ version => $version, created => $created, challenge => $challenge };
}

sub proofWebsiteFile(%)
{	my ($self, %args) = @_;
	my $field     = $args{field};
	my $file      = $args{file};
	my $website   = $args{website};

	$self->_trace("Proving website ownership via json source file '$file'");

	my ($fetch, $json) = $self->_getJSON($field, $file);

	my $results = $self->results;
	$results->{file_fetch} = $fetch;
	$results->{matching_challenges} =
		[ map $self->_validateChallenge($_), grep $_->{website} eq $website, @$json ];

	$self;
}

sub proofWebsiteHTML(%)
{	my ($self, %args) = @_;
	my $field     = $args{field};
	my $website   = $args{website};

	$self->_trace("Proving website via HTML");

	my ($response, $fetch) = get_page $self, $website;

	my $results = $self->results;
	$results->{file_fetch} = $fetch;

	my $dom = XML::LibXML->load_html(string => $response->decoded_content,
		recover           => 2,
		suppress_errors   => 1,
		suppress_warnings => 1,
		no_network        => 1,
		no_xinclude_nodes => 1,
	);
	my $xpc  = XML::LibXML::XPathContext->new($dom->documentElement);
	my @meta = $xpc->findnodes('//meta[@name="open-console.website-owner"]');

	my @defs;
	foreach my $meta (@meta)
	{	my %def = map +($_->nodeName =~ s/^data-//r => $_->value),
			grep $_->isa('XML::LibXML::Attr'),     # strip xmlns
				$meta->attributes;

		push @defs, $self->_validateChallenge(\%def)
			if $website eq ($def{content} //'');
	}

#warn Dumper \@defs;
	$results->{matching_challenges} = \@defs;
	$self;
}

sub proofWebsiteDNS(%)
{	my ($self, %args) = @_;
	my $field     = $args{field};
	my $record    = $args{record};

	$self->_trace("Proving website via DNS record");

	my $results = $self->results;
	my $fetch   = $results->{fetch} = { start => timestamp };

	my @keys  = grep $_->type eq 'DNSKEY', $resolver->send($record, 'DNSKEY', 'IN')->answer;
	$fetch->{got_dnskeys} = timestamp;
	$self->_trace("Collected ".@keys." DNSKEYS records");

	my @sigs  = grep $_->type eq 'RRSIG',  $resolver->send($record, 'RRSIG', 'IN')->answer;
	$fetch->{got_rrsigs}  = timestamp;
	$self->_trace("Collected ".@sigs." RRSIG records");

	my ($status, $rr_txt) = $self->_getRR($field, $record => 'TXT', \@sigs, \@keys);
	$fetch->{txt_dnssec}  = $status;
	$self->_trace("Got ".@$rr_txt." TXT records");
	$self->_trace("DNSSEC status $status");

	my @defs;
	foreach my $rr (@$rr_txt)
	{	foreach my $challenge ($rr->txtdata)
		{	unless(is_valid_token $challenge)
			{	$self->addError(__x"Invalid challenge skipped.");
				next;
			}
			push @defs, +{ challenge => $challenge };
		}
	}

	$results->{matching_challenges} = \@defs;
use Data::Dumper;
warn Dumper $results;
	$self;
}

1;
