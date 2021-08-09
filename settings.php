<?php

// if (is_admin()){
// 	add_action('admin_init', 'wpdb_protect_settings_register');
// }
//
// function wpdb_protect_settings_register() {
//
// 	register_setting(
// 			'general',           // option_group
// 			'wpdb_protect_level' // option_name
// 		);
//
// 	add_settings_field(
// 			'wpdb_protect_id',   // id
// 			'WPDB Protection',   // title
// 			'wpdb_protect_html', // callback
// 			'general',           // page
// 			'default',           // section
// 			[
// 				'label_for' => 'wpdb_protect_id',
// 			],
// 		);
//
// }
//
// function wpdb_protect_html() {
//
// 	global $wpdb;
//
// 	if (!method_exists($wpdb, 'protection_available')) {
//
// 		$paths = wpdb_protect_db_symlink_paths();
// 		$command = 'ln -s ' . esc_html(escapeshellarg($paths[0])) . ' ' . esc_html(escapeshellarg($paths[1])) . ';';
//
// 		echo "
// 			<p><label for='wpdb_protect_command'>The WPDB-Protect class needs to be installed with:</label></p>
// 			<p><input id='wpdb_protect_command' type='text' value='" . esc_attr($command) . "' class='regular-text' readonly='readonly' /></p>";
//
// 	} else if (!$wpdb->protection_available()) {
//
// 		echo "
// 			<p>Not available before PHP 8.x</p>";
//
// 	} else {
//
// 		$value = $wpdb->protection_level();
//
// 		echo "
// 			<select id='wpdb_protect_id' name='wpdb_protect_level'>
// 				<option value='0'" . ($value === 0 ? ' selected="selected"' : '') . ">Off</option>
// 				<option value='1'" . ($value === 1 ? ' selected="selected"' : '') . ">Check for SQLi risks</option>
// 				<option value='2'" . ($value === 2 ? ' selected="selected"' : '') . ">Block SQLi risks (not recommended)</option>
// 			</select>
// 			<p class='date-time-doc'><a href='#'>Documentation on how WPDB projects against SQL Injection Vulnerabilities</a>.</p>";
//
// 	}
//
// }

?>