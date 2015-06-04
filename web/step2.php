<?php
// basically a garbage file - some logic is good to use, but this was pulled from a diff project.
require('conf.php');
require('lib.php');

session_start();

// User is not logged in, redirect
if(empty($_SESSION['oauth_uid'])){
	header('Location: twitter_login.php');
	exit;
}

$sock = stream_socket_client("unix://$socket_file", $errno, $errstr);

// todo: make this error message prettier?

if ($errno) {
	print("<html><body>\n");
	print("something is wrong: <strong>$errstr!</strong><br />\n");
	print("the backend server probably isn't running. kick it.\n");
	print("</body></html>\n");
	exit;
}

// create a connection to our backend server
$ret = login_to_backend(	$sock,
				$app_key,
				$app_secret,
				$_SESSION['oauth_token'],
				$_SESSION['oauth_token_secret'] );

// todo: put in a link to the webpage. we should add that to the conf file.
if ( $ret == "AUTH_ERR" ) {
	print("<html><body>\n");
	print("There seems to be a problem logging you in to twitter. ");
	print("Try hitting back in your browser to restart the process.\n");
	print("</body></html>\n");
	exit;
}

// get username from POST data
$username = $_POST["username"];

// verify username is actually set. redirect if not.
// i remember php did weird stuff with variables being set vs false or something
// hopefully strlen is a safe way to do this and won't barf?
if (strlen($username) < 1) {
	header('Location: twitter_login.php');
	exit;
}

// send username to backend
fwrite($sock, 'USER '.$username."\n");

    // Check RT/REPLY values from form submission
    $retweet = (isset($_POST[retweet]) && $_POST[retweet] == "Retweet") ? 1 : 0;
    $reply = (isset($_POST[reply]) && $_POST[reply] == "Reply") ? 1 : 0;

fwrite($sock, "RT $retweet\n");
fwrite($sock, "REPLY $reply\n");

// kick off the backend processing
fwrite($sock, "GO\n");

// redirect to step3.php, which is our refresh loop
header('Location: step3.php');
