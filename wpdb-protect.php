<?php

/**
 * @package WPDB-Protect
 * @version 1.0.0
 */
/*
Plugin Name: WPDB-Protect
Plugin URI: https://example.com
Description: Experimental WordPress plugin to prevent SQL Injection.
Author: Mike Schinkel and Craig Francis
Version: 1.0.0
Author URI: https://example.com
*/

if (is_admin()){ // admin actions
	register_activation_hook( __FILE__, 'wpdb_protect_activate' );
	register_deactivation_hook( __FILE__, 'wpdb_protect_deactivate' );
	add_action('admin_menu', 'wpdb_protect_menu');
}

function wpdb_protect_db_symlink_paths() {
	return [
			WP_PLUGIN_DIR . '/wpdb-protect/db.php', // not sure we should use `plugin_dir_path( __FILE__ )`
			WP_CONTENT_DIR . '/db.php',
		];
}

function wpdb_protect_activate() {

	list($link_target, $link_path) = wpdb_protect_db_symlink_paths();
	if (!is_file($link_path) && !is_link($link_path)) {
		@symlink($link_target, $link_path);
		// if (is_link($link_path)) {
		// 	require_once( $link_path ); // Needs more steps, as table names like $wpdb->options have not been set.
		// }
	}

	global $wpdb; // Cannot use %t in $wpdb->prepare() as it might not be available (symlink might not have worked)

	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}wpdb_warnings (
			file_path varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
			file_line int(11) NOT NULL,
			file_arg int(11) NOT NULL,
			file_mtime datetime NOT NULL,
			value text COLLATE utf8mb4_unicode_ci NOT NULL,
			backtrace text COLLATE utf8mb4_unicode_ci NOT NULL,
			url text COLLATE utf8mb4_unicode_ci NOT NULL,
			created datetime NOT NULL,
			PRIMARY KEY (file_path,file_line,file_arg)
		)";

	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

	dbDelta([$sql]); // Use an array so the string is not split.

	add_option('wpdb_protect_level', -1); // Cannot easily replace $wpdb, so we are still working with the original version

}

function wpdb_protect_deactivate() {

	global $wpdb; // Cannot use $wpdb->prepare() as %t might not be available

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wpdb_warnings" ); // dbDelta does not support DROP TABLE

	delete_option('wpdb_protect_level');

	list($link_target, $link_path) = wpdb_protect_db_symlink_paths();
	if (is_link($link_path) && readlink($link_path) == $link_target) {
		@unlink($link_path);
	}

}

function wpdb_protect_menu() {
	add_menu_page(
			'View WPDB Warnings',        // page_title
			'WPDB Warnings',             // menu_title
			'manage_options',            // capability... where 'manage_options' is an admin-level user.
			'wpdb-warnings',             // menu_slug
			'wpdb_protect_warmings_page' // function
		);
}

function wpdb_protect_warmings_page() {
	include __DIR__ . '/warnings.php';
}

?>