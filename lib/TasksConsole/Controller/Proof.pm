# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

package TasksConsole::Controller::Proof;
use Mojo::Base 'TasksConsole::Controller';

use TasksConsole::Prover::Website ();

use Log::Report 'open-console-tasks';

sub registerTasks($)
{	my ($class, $minion) = @_;
	$minion->add_task(verifyWebsiteURL => \&_verifyWebsiteURL);
}

sub job()
{	my $self = shift;
	my $jobid   = $self->param('jobid');
    my $session = OpenConsole::Session::Task->job($jobid, controller => $self);
	$session->reply;
}

sub _verifyWebsiteURL($$)
{	my ($job, $args) = @_;
	my $session;

	try {
		$session = TasksConsole::Prover::Website->new(lang => $args->{lang});
		$session->checkWebsite(%$args);
	};
	$session->internalError($@->wasFatal) if $@;

use Data::Dumper;
if(open my $d, '>', '/tmp/debug') { $d->print(Dumper $session); $d->close }

	$job->finish($session->_data);
}

sub verifyWebsiteURL($)
{	my $self    = shift;

	my $session = OpenConsole::Session::Task->create({}, lang => 'en', controller => $self);
	my $data    = $self->req->json;

	my $field   = $data->{field} or panic "No field";
	my $url     = $data->{url}   or panic "No url to check";

	my $settings = {};
	my $jobid   = $self->startJob(verifyWebsiteURL => { field => $field, website => $url }, %$settings);
	$session->jobQueued($jobid, $settings);
	$session->reply;
}

1;
