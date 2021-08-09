<?php

//--------------------------------------------------
// Setup

	if (!defined('ABSPATH')) {
		exit();
	}

	global $wpdb;

	$enable_command = NULL;
	$available = false;

//--------------------------------------------------
// Testing

	// // $fragment = 'ID = ' . ($_GET['id'] ?? rand(1, 5));
	// $fragment = $wpdb->prepare('ID = %d', 1);
	// $sql = $wpdb->prepare('SELECT %i, %i FROM %t WHERE %r AND user_status IN (%...d)', ['ID', 'user_login', 'users', $fragment, [0, 1, 2]]);
	// echo '<pre>';
	// print_r($sql);
	// print_r($wpdb->get_results($sql));
	// echo '</pre>';
	// exit();

//--------------------------------------------------
// Processing

	if (!method_exists($wpdb, 'protection_available')) {

		//--------------------------------------------------
		// Command to enable manually

			$paths = wpdb_protect_db_symlink_paths();

			$enable_command = 'ln -s ' . escapeshellarg($paths[0]) . ' ' . escapeshellarg($paths[1]) . ';';

	} else if ($wpdb->protection_available()) {

		//--------------------------------------------------
		// Available

			$available = true;

			$value_level = $wpdb->protection_level();

		//--------------------------------------------------
		// Update level

			if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {

				if (!isset($_POST['wpdb-protect-csrf']) || ! wp_verify_nonce($_POST['wpdb-protect-csrf'], 'wpdb-protect-save')) {

					wp_nonce_ays('');
					exit();

				} else {

					$value_level = intval($_POST['wpdb_protect_level'] ?? 0);

					update_option('wpdb_protect_level', $value_level, false); // Probably should not autoload, as it's returned early in the process.

				}

			}

		//--------------------------------------------------
		// Current warnings

			$page_size = 20;
			$page_number = intval($_GET['offset'] ?? 1);
			if ($page_number < 1) {
				$page_number = 1;
			}
			$page_offset = (($page_number - 1) * $page_size);

			$sql = "SELECT SQL_CALC_FOUND_ROWS
						w.file_path,
						w.file_line,
						w.file_arg,
						w.file_mtime,
						w.value,
						w.backtrace,
						w.url,
						DATE_FORMAT(w.created, '%D %b, %H:%S') AS created,
						0 AS deleted
					FROM
						%t AS w
					ORDER BY
						w.created DESC,
						w.file_path,
						w.file_line,
						w.file_arg
					LIMIT
						%d, %d"; // Sort just to keep files together (while still focusing on recent requests).

			$sql = $wpdb->prepare($sql, 'wpdb_warnings', $page_offset, $page_size);

			$warnings = $wpdb->get_results($sql);

		//--------------------------------------------------
		// Pagination

			$warning_count = $wpdb->get_var('SELECT FOUND_ROWS()');

			$page_count = ceil($warning_count / $page_size);
			if ($page_count < 1) {
				$page_count = 1;
			}
			if ($page_number > $page_count) {
				$warnings = NULL;
			}

		//--------------------------------------------------
		// Auto delete entries

			$auto_delete_enabled = (($_GET['auto-delete'] ?? '') == 'true');
			$auto_delete_url = add_query_arg('auto-delete', ($auto_delete_enabled ? false : 'true'));
			$auto_delete_files = [];

			if ($auto_delete_enabled) {
				foreach ($warnings as $k => $warning) {

					if (in_array($warning->file_path, $auto_delete_files)) {

						$warning->deleted = true; // Already deleted

					} else {

						$file_path = realpath(ABSPATH . $warning->file_path);
						if ($file_path) {

							$file_mtime = filemtime($file_path);

							if ($file_mtime > strtotime($warning->file_mtime)) {

								$warning->deleted = true; // Just show it's deleted (confirmation, and removing entries makes it look weird as pagination has already happened)

								$sql = "DELETE FROM
											%t
										WHERE
											file_path = %s";

								$wpdb->query( $wpdb->prepare($sql, 'wpdb_warnings', $warning->file_path) ); // Just delete all entries for this file

								$auto_delete_files[] = $warning->file_path;

							}

						}

					}

				}
			}

	}

?>

<div class="wrap">
	<h1>WPDB Warnings</h1>

	<?php if ($enable_command) { ?>

		<p><label for='wpdb_protect_command'>The WPDB-Protect class needs to be installed with:</label></p>
		<p><input id='wpdb_protect_command' type='text' value='<?= esc_attr($enable_command) ?>' class='regular-text' readonly='readonly' /></p>

	<?php } else if (!$available) { ?>

		<p>Not available before PHP 8.x</p>

	<?php } else { ?>

		<form method="post">

			<p>
				<label for="wpdb_protect_id">Protection:</label>
				<select id='wpdb_protect_id' name='wpdb_protect_level'>
					<option value='0'<?= ($value_level === 0 ? ' selected="selected"' : '') ?>>Off</option>
					<option value='1'<?= ($value_level === 1 ? ' selected="selected"' : '') ?>>Check for SQLi risks, Log</option>
					<option value='2'<?= ($value_level === 2 ? ' selected="selected"' : '') ?>>Check for SQLi risks, Log, Show Warnings (for development)</option>
					<option value='3'<?= ($value_level === 3 ? ' selected="selected"' : '') ?>>Check for SQLi risks, Log, and Block (not recommended)</option>
				</select>
			</p>

			<?php
				wp_nonce_field( 'wpdb-protect-save', 'wpdb-protect-csrf' );
				submit_button();
			?>

			<?php if ($warnings === NULL) { ?>

				<p><a href='<?= esc_url(add_query_arg('offset', false)) ?>'>Back</a></p> <!-- Cannot do a redirect (headers already sent) -->

			<?php } else { ?>

				<p><a href='<?= esc_url($auto_delete_url) ?>'>Auto Delete Warnings</a>: <strong><?= ($auto_delete_enabled ? 'On' : 'Off') ?></strong> - This works by removing entries if the file has been edited since the warning was raised.</p>

				<table class="widefat">
					<thead>
						<tr>
							<th>File</th>
							<th>Value</th>
							<th>Created</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($warnings as $warning) { ?>
							<tr>
								<td><?= ($warning->deleted ? '<del>' : '') . esc_html($warning->file_path . ':' . $warning->file_line) . ($warning->deleted ? '</del>' : '') ?></td>
								<td><?= ($warning->deleted ? '<del>' : '') . esc_html($warning->value)                                 . ($warning->deleted ? '</del>' : '') ?></td>
								<td><?= ($warning->deleted ? '<del>' : '') . esc_html($warning->created)                               . ($warning->deleted ? '</del>' : '') ?></td>
							</tr>
						<?php } ?>
					</tbody>
				</table>

				<p>
					Warnings: <strong><?= esc_html($warning_count) ?></strong>
					<?php
						if ($page_count > 1) {
							echo ' | Page: ';
							for ($k = 1; $k <= $page_count; $k++) {
								if ($k > 1) {
									echo ', ';
								}
								if ($k == $page_number) {
									echo '<strong>';
								}
								echo "<a href='" . esc_url(add_query_arg('offset', $k)) . "'>" . esc_html($k) . "</a>";
								if ($k == $page_number) {
									echo '</strong>';
								}
							}
						}
					?>
				</p>

			<?php } ?>

		</form>

	<?php } ?>

</div>
