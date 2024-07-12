# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

package TasksConsole;
use Mojo::Base 'OpenConsole';

use Log::Report 'open-console-tasks';

use Mojo::Pg   ();

use feature 'state';

use OpenConsole::Util           qw(reseed_tokens);

use TasksConsole::Controller::Proof ();

use constant {
	POSTGRESQL_SERVER => 'localhost:5432',
	MINION_USER       => 'ocminion',
	MINION_DATABASE   => 'ocminion',
};

=chapter NAME

TasksConsole - Open Console Batch processing, a REST service

=chapter SYNOPSIS

  morbo script/tasks_console &

=chapter DESCRIPTION
This module manages Open Console's batch processing: processes which
take too long to be run by website processes are run as tasks by separate
daemons.  The web-clients only poll these daemon processes to see whether
the result is ready.

This module uses M<Mojolicious> with M<Minion> to administer the tasks.
Minion also offers a nice admin interface.

The process which is managed by Minion is a B<job>.  The job in combination
with a server is a B<task>.  Therefore, callers with use a task identifier,
not a job identifier.

=chapter METHODS

=section Constructors
=cut

#----------------
=section Attributes
=cut

#----------------
=section Databases
=cut

#----------------
=section Running the daemons

=method startup
This method will run once at the Mojolicious server start.  It does not start the
Minion workers, but only the routing system.
=cut

sub startup
{	my $self = shift;
	$self->SUPER::startup(@_);

	my $config = $self->config;

	### Connect to the minion support database

	my %db     = %{$config->{tasksdb} || {}};
	my $dbuser = delete $db{dbuser}   || MINION_USER;
	my $dbpwd  = delete $db{dbpasswd} or panic "Task database configuration requires a password.";
	my $conn   = Mojo::URL->new;
	$conn->scheme('postgresql');
	$conn->host_port(delete $db{dbserver} || POSTGRESQL_SERVER);
	$conn->userinfo("$dbuser:$dbpwd");  # no colon in username!
	$conn->path(delete $db{dbname} || MINION_DATABASE);

	#XXX it seems not possible to pass the Mojo::URL as object for Mojo::Pg :-(
	# 'state' makes the connection being reused.
	$self->helper(pg => sub { state $pg = Mojo::Pg->new($conn->to_unsafe_string) });

	### Minion

	my %minconf = %{$config->{minion} || {}};
	my $plugin  = $self->plugin('Minion::Workers' => {
		Pg      => $self->pg,
		workers => $minconf{workers} // 3,
		manage  => 1,
	});
	my $minion  = $self->minion;
	TasksConsole::Controller::Proof->registerTasks($minion);

	### Admin interface

	my $admin = $config->{minion_admin} || {};
	if(delete $admin->{enabled})
	{	# management under /minion
		$::app->plugin('Minion::Admin' => %$admin);
	}

	### Routes

	my $r = $self->routes;

	$r->post('/job/:jobid')->to('proof#job');   # generic poll point

	$r->post('/proof/verifyWebsiteURL')->to('proof#verifyWebsiteURL');
}

1;
