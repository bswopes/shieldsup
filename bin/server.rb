#!/usr/bin/env ruby

require 'socket'
require 'twitter'
require 'logger'
require 'yaml'
require 'mysql2'

$DEBUG = true

CONFIG_FILE   = File.join(File.dirname(__FILE__), '..', 'conf.yaml')

$log = Logger.new(STDOUT)
$log.level = Logger::DEBUG



# return the userinfo for the authenticated user
# this is how we verify that our credential are good
# returns: userdata
def get_userdata
	begin
		userdata = Thread.current['conn']['twitter'].verify_credentials
	rescue Twitter::Error::Unauthorized => error
		$log.error("AUTH: Fail (Unauthorized)")
		Thread.current['client'].puts("AUTH_ERR")
		return false
	rescue Twitter::Error::TooManyRequests => error
		$log.warn("ERR_TWITTER: Rate limited (#{error.rate_limit.reset_in})")
		Thread.current['client'].puts("ERR_TWITTER Rate limited until #{error.rate_limit.reset_in}")
		return false
	end

	userdata
end



# get the most recent tweets
def get_timeline
	$log.warn("get timeline")

	begin
		tweets = Thread.current['conn']['twitter'].user_timeline(Thread.current['conn']['user'], {count: 200, include_rts: false})
	rescue Twitter::Error::TooManyRequests => error
		$log.warn("AUTH: Rate limited (#{error.rate_limit.reset_in})")
		sleep error.rate_limit.reset_in
		retry
	rescue Twitter::Error::NotFound => error
		$log.warn("ERROR: user not found (#{Thread.current['conn']['user']})")
		return false
	end

	$log.warn("finished timeline")

	return tweets
end



### old code, clean up
### todo: more generic error checking
def get_follower_ids 
	begin
		follower_ids = Thread.current['conn']['twitter'].follower_ids
	rescue Twitter::Error::TooManyRequests => error
		$log.warn("AUTH: Rate limited (#{error.rate_limit.reset_in})")
		sleep error.rate_limit.reset_in
		retry
	end

	follower_ids
end



### old code, clean up
### todo: more generic error checking
def get_friend_ids
	begin
		friend_ids = Thread.current['conn']['twitter'].friend_ids
	rescue Twitter::Error::TooManyRequests => error
		$log.warn("AUTH: Rate limited (#{error.rate_limit.reset_in})")
		sleep error.rate_limit.reset_in
		retry
	end

	friend_ids
end



# connect to our db
# return: db object
def connect_to_db
	Mysql2::Client.new(	:host => $config['db']['host'],
				:username => $config['db']['username'],
				:password => $config['db']['password'],
				:database => $config['db']['database'] )
end



# check for db entry/status
# return: row or false if not found
def get_db_status
	m = connect_to_db

	m.query("SELECT status FROM jobs WHERE userid = '#{Thread.current['conn']['userdata'].id}'").each do |row|
		return row['status']
	end

	return false
end



# create a new job in our database 
# todo: add values for rt/replies/userid
def create_db_job
	m = connect_to_db
	username = m.escape(Thread.current['conn']['user'])
	m.query("INSERT INTO jobs (userid, target_username, added, status) VALUES ('#{Thread.current['conn']['userdata'].id}', '#{username}', NOW(), 'RUNNING' )")
end



# update entry in jobs table to show as being done
def update_db_job_done
	m = connect_to_db
	m.query("UPDATE jobs SET status = 'DONE' WHERE userid = '#{Thread.current['conn']['userdata'].id}'")
end



# delete an entry from the jobs table
def remove_db_job
	m = connect_to_db
	m.query("DELETE from jobs WHERE userid = '#{Thread.current['conn']['userdata'].id}'")
end



# print output of file
def get_list_command
	# check db entry to verify status = done
	if is_job_done == false 
		# job is not in done state 
		# todo: error message here
		Thread.exit
	end
	
	# print file to client
	read_from_file

	# delete file 
	delete_file

	# remove db entry
	remove_db_job
end



# get up to 100 userids that have retweeted a given tweetid
# returns: array of userids
def get_retweeters(tweetid)
	# todo: drop ids_only so it returns the full userdata
	# we should parse this userdata for the username.
	# we can also save ourselves some api calls later by checking to see if
	# we're following that user here.
	# this means we won't be returning a simple array, but an array of hashes
	begin
		userids = Thread.current['conn']['twitter'].retweeters_of(tweetid, {ids_only: true})
	rescue Twitter::Error::TooManyRequests => error
		$log.warn("AUTH: Rate limited (#{error.rate_limit.reset_in})")
		sleep error.rate_limit.reset_in
		retry
	rescue Twitter::Error::NotFound => error
		$log.warn("ERROR: user not found (#{Thread.current['conn']['user']})")
		return false
	end

	userids
end



# get the most retweeted tweetids from a user
# returns: array of tweet ids
def get_top_tweets(tweets)
	metadata = {}
	top = Array.new

	# create a new data structure with the retweet count
	tweets.each do | tweet |
		metadata[tweet.id] = tweet.retweet_count
	end

	# there's a better way to do this. but i'm tired and don't care.
	# sort the data structure we just created, take the top 12, and shove
	# the tweet id into a new array that we return at the end.
	metadata.sort_by{ | k, v| v }.reverse.take(12).each do |t|
		top << t[0]
	end

	top
end



# delete file
def delete_file
	filename = File.join($config['temp_dir'], "#{Thread.current['conn']['userdata'].id}.txt")
	File.delete(filename)
end



# write userids to temp file to be grabbed later
# filename = authuserid.txt
def write_to_file(userids)
	# todo: check when prog first runs to see if temp_dir is set/exists
	filename = File.join($config['temp_dir'], "#{Thread.current['conn']['userdata'].id}.txt")

	# delete file if exists
	if File.exists?(filename)
		$log.warn("#{filename} already exists, removing.")
		File.delete(filename)
	end

	# write to file
	# todo: this should be a hash, not an array
	# syntax: userid username isfriend isfollower
	File.open(filename, "w+") do |f|
		userids.each do |id|
			f.puts("#{id} null 0 0")
		end
	end
end



# read data from temp file
# filename = authuserid.txt
def read_from_file
	filename = File.join($config['temp_dir'], "#{Thread.current['conn']['userdata'].id}.txt")

	# verify file exists
	if ! File.exists?(filename)
		$log.warn("#{filename} does not exist.")
		# update database with some kind of error
		return false
	end

	Thread.current['client'].puts("BEGIN_LIST")

	# read from file
	File.open(filename, "r") do |f|
		f.each_line do |line|
			Thread.current['client'].puts(line)
		end
	end

	Thread.current['client'].puts("END_LIST")
end



# thread function for starting to kick off crap to twitter.
def go_thread 
	userids = Array.new

	# create db entry
	create_db_job

	# todo: verify rt or reply is set to true - must have at least one set 

	# pull down latest 200 tweets from user
	tweets = get_timeline

	# unrecoverable error
	if ! tweets 
		# todo: set an error state in the db of some sort
		return
	end

	# get top tweet ids
	top_tweets = get_top_tweets(tweets)

	# pull down retweet ids from top tweets
	# todo: turn this into hash, not array
	top_tweets.each do | tweetid |
		# pops these ids into the userids array, removes dupes
		userids = userids|get_retweeters(tweetid)
	end
	
	# todo: if reply is set, search API for username, get latest results (what is limit?)
	# looks like appropriate call is mentions_timeline - can pull down 800 tweets

	# todo: pull down friends list and compare
	# start with get_friend_ids function (above)

	# todo: pull down followers list and compare
	# start with get_follower_ids function (above)
	# if we pull down full userdata instead of just ids in our previous requests,
	# we can skip this step and save ourselves some api calls.

	# create temp file
	write_to_file(userids)

	# change db status to done
	update_db_job_done
end



# kick off a thread for API requests to twitter
# todo: check to see if a job is in DONE state - we shouldn't be accepting new requests.
def go_command
	# see if a job is already running. cheap and easy way of doing it.
	# should probably be more graceful about it
	return if is_job_running
	return if is_job_done 

	# copy our connection data out to a new variable
	conn = Thread.current['conn']

	# spin up a new thread
	Thread.new do
		Thread.current['conn'] = conn
		go_thread	
	end
end



# decide what to do based upon the command given
# return: false on error/exit, command after execution
def parse_command(command)
	case command
	when /^user (.*)$/
		Thread.current['conn']['user'] = $1
		return true 
	when /^rt (.*)$/
		Thread.current['conn']['rt'] = $1
		return true 
	when /^reply (.*)$/
		Thread.current['conn']['reply'] = $1
		return true
	when "status"
		status_command
	when "go"
		go_command
	when "get_list"
		get_list_command
	when "exit"
	else
		$log.error("[#{Thread.current['conn']['userdata'].id}] ERR_OTHER: Command #{command} unknown")
		Thread.current['client'].puts("ERR_OTHER Unknown command when talking to backend")
	end

	# already returned true for things that require more input
	# this seems less than intuitive, though.
	false	
end



# see if a job is running or done
# returns: true if job found, false if not
# todo: error handling
def status_command
	# query database to get status of possible existing job 
	if is_job_running
		$log.info("[#{Thread.current['conn']['userdata'].id}] WAIT")
		Thread.current['client'].puts("WAIT")
		return true
	elsif is_job_done
		$log.info("[#{Thread.current['conn']['userdata'].id}] DONE")
		Thread.current['client'].puts("DONE")
		return true
	end

	false
end


# get a line from the client, downcase and remove trailing whitespace
# return: command
def get_command
	command = Thread.current['client'].gets
	return unless command

	command.downcase!
	command.chomp!

	$log.debug("[#{Thread.current['conn']['userdata'].id}] COMMAND: #{command}")

	command
end



# authenticate to twitter
# return: twitter client object 
def twitter_auth
	$log.debug("Authenticating")

	# get auth info from client
	# app auth - don't bother saving this into globals
	consumer_key = Thread.current['client'].gets.chop
	$log.debug("consumer_key: #{consumer_key}")
	consumer_secret = Thread.current['client'].gets.chop
	$log.debug("consumer_secret: #{consumer_secret}")

	# user tokens should be saved as thread variables
	Thread.current['conn']['oauth_token'] = Thread.current['client'].gets.chop
	$log.debug("access_token: #{Thread.current['conn']['oauth_token']}")
	Thread.current['conn']['oauth_secret'] = Thread.current['client'].gets.chop
	$log.debug("oauth_secret: #{Thread.current['conn']['oauth_secret']}")

	# attempt to connect to auth to twitter 
	# do i need to put an error handler here?
	Thread.current['conn']['twitter'] = Twitter::REST::Client.new do |config|
		config.consumer_key = consumer_key
		config.consumer_secret = consumer_secret
		config.access_token = Thread.current['conn']['oauth_token'] 
		config.access_token_secret = Thread.current['conn']['oauth_secret'] 
	end

	if Thread.current['conn']['twitter'] 
		Thread.current['client'].puts("AUTH_OK")
		return true
	else
		$log.error("AUTH_ERR: #{Thread.current['conn']['oauth_token']}")
		Thread.current['client'].puts("AUTH_ERR")
		return false
	end
end



# simple function just to see if job is currently running.
# returns: true if running, false if not.
def is_job_running
	get_db_status =~ /^RUNNING$/ ? true : false
end



# simple function just to see if job is done.
# returns: true if done, false if not.
def is_job_done
	get_db_status =~ /^DONE$/ ? true : false
end



# main thread function for incoming connections
def handle_client
	$log.info("New connection")

	# verify auth keys for every connection
	# check credentials - if busted, exit.
	if twitter_auth == false
		Thread.current['client'].close
		return
	end

	# get userdata for authed account
	Thread.current['conn']['userdata'] = get_userdata

	# if this isn't set, something went wrong. we've already returned the error code.
	if Thread.current['conn']['userdata'] == false
		Thread.current['client'].close
		return
	end

	$log.info("[#{Thread.current['conn']['userdata'].id}] AUTH: Success")

	while true
		command = get_command
		# return if command is empty
		break unless command
		# return if parse_command is false
		break unless parse_command(command) 
	end

	$log.info("Closing connection")
	Thread.current['client'].close
end



# main program loop
def main
	# read our config
	$config = YAML.load_file(CONFIG_FILE)

	# not strictly necessary, but for the purpose of making this more readable.
	socket_file = File.join($config['base_dir'], $config['socket_file'])

	# start server
	if File.exists?(socket_file)
		$log.warn("#{$config['socket_file']} already exists, removing.")
		File.delete(socket_file)
	end

	server = UNIXServer.new(socket_file)
	# Handle cases where the backend process and web server do not share a username. TODO: do we need to add proper security for this case?
	File.chmod($config['socket_mode'], socket_file)

	while true
		client = server.accept

		Thread.start(client) do |c|
			# set up a variable to store our connection data
			Thread.current['conn'] = {}
			Thread.current['client'] = c

			handle_client
		end
	end
end



# if the process gets killed, clean up by removing our socket file
trap('INT') {
	$log.info("Exiting.")

	if File.exists?(File.join($config['base_dir'], $config['socket_file']))
		File.delete(File.join($config['base_dir'], $config['socket_file']))
	end

	exit
}

main
