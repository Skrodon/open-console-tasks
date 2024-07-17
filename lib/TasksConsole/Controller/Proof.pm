# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

package TasksConsole::Controller::Proof;
use Mojo::Base 'TasksConsole::Controller';

use TasksConsole::Prover::Website ();

use Log::Report 'open-console-tasks';

sub registerTasks($)
{	my ($class, $minion) = @_;
	$minion->add_task(verifyWebsiteURL => \&_verifyWebsiteURL);
	$minion->add_task(proofWebsiteFile => \&_proofWebsiteFile);
	$minion->add_task(proofWebsiteHTML => \&_proofWebsiteHTML);
}

sub job()
{	my $self = shift;
	my $jobid = $self->param('jobid');
	my $job   = $::app->minion->job($jobid);

    my $session = OpenConsole::Session::Task->job($job, controller => $self);
	$session->reply;
}

### verifyWebsiteURL

sub _verifyWebsiteURL($$)
{	my ($job, $args) = @_;
	my $session = TasksConsole::Prover::Website->new(lang => $args->{lang});
	try { $session->checkWebsite(%$args) };
	$session->internalError($@->wasFatal) if $@;
	$job->finish($session->_data);
}

sub verifyWebsiteURL()
{	my $self   = shift;
	my $req    = $self->req->json;
	my %params = (
		field   => ($req->{field}	// panic "No field"),
		website => ($req->{website}	// panic "No website to check"),
	);
	$self->taskStart(verifyWebsiteURL => {}, $req, \%params, {})->reply;
}

### proofWebsiteFile

sub _proofWebsiteFile($$)
{	my ($job, $args) = @_;
	my $session = TasksConsole::Prover::Website->new(lang => $args->{lang});
	try { $session->proofWebsiteFile(%$args) };
	$session->internalError($@->wasFatal) if $@;
	$job->finish($session->_data);
}

sub proofWebsiteFile()
{	my $self   = shift;
	my $req    = $self->req->json;
	my %params = (
		field   => ($req->{field}	// panic "No field"),
		file    => ($req->{file}	// panic "No file to load"),
		website => ($req->{website}	// panic "No website"),
	);
	$self->taskStart(proofWebsiteFile => {}, $req, \%params, {})->reply;
}

### proofWebsiteHTML

sub _proofWebsiteHTML($$)
{	my ($job, $args) = @_;
	my $session = TasksConsole::Prover::Website->new(lang => $args->{lang});
	try { $session->proofWebsiteHTML(%$args) };
	$session->internalError($@->wasFatal) if $@;
	$job->finish($session->_data);
}

sub proofWebsiteHTML()
{	my $self   = shift;
	my $req    = $self->req->json;
	my %params = (
		field   => ($req->{field}	// panic "No field"),
		website => ($req->{website}	// panic "No website"),
	);
	$self->taskStart(proofWebsiteHTML => {}, $req, \%params, {})->reply;
}

1;
