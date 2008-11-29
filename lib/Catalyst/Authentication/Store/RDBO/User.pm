package Catalyst::Authentication::Store::RDBO::User;
use strict;
use warnings;

use base qw/Catalyst::Authentication::User/;
use base qw/Class::Accessor::Fast/;

BEGIN {
	__PACKAGE__->mk_accessors(qw/config user_class manager_class _user _roles/);
}

sub new
{
	my ($class, $config, $c) = @_;

	my $self = {
		user_class => $config->{'user_class'},
		manager_class => $config->{'manager_class'}
			? $config->{'manager_class'}
			: $config->{'user_class'} . '::Manager',
		config    => $config,
		_roles    => undef,
		_user     => undef
	};

	bless $self, $class;

	## Note to self- add handling of multiple-column primary keys.
	if(!exists($self->config->{'id_field'})) {
		my @pks = $self->user_class->meta->primary_key->column_names;
		if($#pks == 0) {
			$self->config->{'id_field'} = $pks[0];
		} else {
			Catalyst::Exception->throw("user table does not contain a single primary key column - please specify 'id_field' in config!");
		}
	}

	if(!$self->user_class->meta->column($self->config->{'id_field'})) {
		Catalyst::Exception->throw("id_field set to " . $self->config->{'id_field'} . " but user table has no column by that name!");
	}

	## if we have lazyloading turned on - we should not query the DB unless something gets read.
	## that's the idea anyway - still have to work out how to manage that - so for now we always force
	## lazyload to off.
	$self->config->{lazyload} = 0;

	return $self;
}

sub _fetch_first
{
	my ($self, $query ) = @_;
	my $results = $self->manager_class->get_objects(
		query => $query,
		object_class => $self->user_class,
		limit => 1,
	);
	if( ! $results || ! @$results) {
		return undef;
	}

	return $results->[0];
}

sub load
{
	my ($self, $authinfo, $c) = @_;

	my $rdbo_config = 0;

	if(exists($authinfo->{'rdbo'})) {
		$authinfo          = $authinfo->{'rdbo'};
		$rdbo_config = 1;
	}

	# User can provide an arrayref containing the arguments to search on
	# the user class by providing a 'rdbo' authinfo hash.
	if($rdbo_config && exists($authinfo->{'searchargs'})) {
		$self->_user( $self->_fetch_first( $authinfo->{'searchargs'}));
	} else {
		# merge the ignore fields array into a hash - so we can do an
		# easy check while building the query
		my %ignorefields = map { $_ => 1 } @{ $self->config->{'ignore_fields_in_find'} };
		my $searchargs = {};

		# now we walk all the fields passed in, and build up a search hash.
		foreach my $key (grep { !$ignorefields{$_} } keys %{$authinfo}) {
			if($self->user_class->meta->column($key)) {
				$searchargs->{$key} = $authinfo->{$key};
			}
		}
		if(keys %{$searchargs}) {
			$self->_user($self->_fetch_first( [ %$searchargs ]));
		} else {
			Catalyst::Exception->throw("User retrieval failed: no columns from " . $self->config->{'user_model'} . " were provided");
		}
	}

	if($self->get_object) {
		return $self;
	} else {
		return undef;
	}

}

sub supported_features
{
	my $self = shift;

	return {
		session => 1,
		roles   => 1,
	};
}

sub roles
{
	my ($self) = shift;

	## shortcut if we have already retrieved them
	if(ref $self->_roles eq 'ARRAY') {
		return (@{ $self->_roles });
	}

	my @roles = ();
	if(exists($self->config->{'role_column'})) {
		my $role_data = $self->get($self->config->{'role_column'});
		if($role_data) {
			@roles = split /[\s,\|]+/, $self->get($self->config->{'role_column'});
		}
		$self->_roles(\@roles);
	} elsif(exists($self->config->{'role_relation'})) {
		Catalyst::Exception->throw('role_relation not yet supported');
	} else {
		Catalyst::Exception->throw("user->roles accessed, but no role configuration found");
	}

	return @{ $self->_roles };
}

sub for_session
{
	my $self = shift;

	return $self->get($self->config->{'id_field'});
}

sub from_session
{
	my ($self, $frozenuser, $c) = @_;

	my $id = $frozenuser;

	return $self->load({ $self->config->{'id_field'} => $id }, $c);
}

sub get
{
	my ($self, $field) = @_;

	if($self->_user->can($field)) {
		return $self->_user->$field;
	} else {
		return undef;
	}
}

sub get_object
{
	my ($self, $force) = @_;

	return $self->_user;
}

sub obj
{
	my ($self, $force) = @_;

	return $self->get_object($force);
}

sub AUTOLOAD
{
	my $self = shift;
	(my $method) = (our $AUTOLOAD =~ /([^:]+)$/);
	return if $method eq "DESTROY";

	$self->_user->$method(@_);
}

1;
