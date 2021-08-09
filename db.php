<?php

class wpdb_protect_class extends wpdb {

	protected $protection_level = NULL;

	public function __construct($dbuser, $dbpassword, $dbname, $dbhost) {
		parent::__construct($dbuser, $dbpassword, $dbname, $dbhost);
	}

	public function protection_available() {
		if (function_exists('is_literal') && is_literal('a') === true && is_literal(sprintf('a')) === false) {
			return true;
		}
		return false;
	}

	public function protection_level() {

			// Maybe check wp_is_recovery_mode() and/or wp_installing()?

		if ($this->protection_level === NULL) {
			if (!$this->protection_available()) {

				$this->protection_level = -2; // Not available

			} else if (!$this->ready) {

				return -1; // Not setup yet (running SET NAMES)

			} else {

				$this->protection_level = -1; // Init mode, avoiding infinite loop (while a query gets the option value)

				// Cannot call get_option(), as it has too many dependencies, like wp_cache_get()

				$suppress = $this->suppress_errors();
				$row      = $this->get_row("SELECT option_id, option_value FROM $this->options WHERE option_name = 'wpdb_protect_level' LIMIT 1");
				$this->suppress_errors( $suppress );

				if ( is_object( $row ) ) {
					$this->protection_level = intval($row->option_value);
					if ($this->protection_level === -1) {
						$this->protection_level = ($this->protection_available() ? 1 : 0); // Technically this will always be true, but things might change.
						$this->query( $this->prepare( "UPDATE $this->options SET option_value = %s WHERE option_id = %d", $this->protection_level, $row->option_id ) );
					}
				} else {
					$this->protection_level = -3;
				}

			}
		}

		return $this->protection_level;

	}

	public function protection_check($value, $arg_number) {
		if (is_array($value)) {
			foreach ($value as $k => $v) {
				$this->protection_check($v, ($arg_number === NULL ? $k : $arg_number . '[' . $k . ']'));
			}
		} else if ($this->protection_level() > 0 && !is_literal($value) && !$value instanceof wpdb_sql_fragment) {

			$backtrace = [];
			$file = NULL;
			foreach (debug_backtrace() as $entry) {
				if (isset($entry['file'])) {
					$path = str_replace(ABSPATH, '', realpath($entry['file']));
					if ($path !== 'wp-content/plugins/wpdb-protect/db.php' && $path !== 'wp-includes/wp-db.php') {
						if ($file === NULL) {
							$file = ['path' => $path, 'line' => $entry['line'], 'mtime' => date('Y-m-d H:i:s', filemtime($entry['file']))];
						}
						$backtrace[] = $path . ':' . $entry['line'];
					}
				}
			}

			if ($file === NULL) {
				$file = ['path' => 'N/A', 'line' => 0, 'mtime' => 0];
			}

			$this->replace($this->prefix . 'wpdb_warnings', [
					'file_path'  => $file['path'],
					'file_line'  => $file['line'],
					'file_arg'   => $arg_number,
					'file_mtime' => $file['mtime'],
					'value'      => $value,
					'url'        => ($_SERVER['REQUEST_URI'] ?? 'N/A'),
					'backtrace'  => implode("\r\n", $backtrace),
					'created'    => date('Y-m-d H:i:s'),
				]);

			if ($this->protection_level() == 2) {

				echo '
					<p>' . esc_html($file['path'] . ':' . $file['line']) . '</p>
					<pre>' . esc_html($value) . '</pre>';

			} else if ($this->protection_level() == 3) {

				exit('A possible SQL Injection vulnerability has been found.');

			}

		}
	}

	// public function protection_debug($value) {
	// 	if ($this->protection_level() > 0 && !is_literal($value) && !$value instanceof wpdb_sql_fragment) {
	// 		echo '<pre>';
	// 		var_dump($value);
	// 		echo '</pre>';
	// 	}
	// }

	public function prepare($query, ...$args) {

		$this->protection_check($query, 0);

		if (true) {

				// A proof of concept, to add support some additional placeholders:
				//   %i = Identifier
				//   %t = Table Identifier
				//   %r = Raw SQL, provided as `wpdb_sql_fragment`

				// This implementation does NOT support formatting strings.

			if ( is_array( $args[0] ?? NULL ) && count( $args ) === 1 ) { // $passed_as_array
				$args = $args[0];
			}

			$new_query = [];
			$new_args = [];
			preg_match_all('/(?<!%)%(\.\.\.)?([itrsdF])\b/', $query, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

			if (count($matches) !== count($args)) {
				exit('The query does not contain the correct number of placeholders (' . count($matches) . ' vs ' . count($args) . ')' . "\n\n" . '<pre>' . esc_html($query) . '</pre>');
			}

			$replacements = array_fill(0, count($matches), true);

			foreach (array_reverse($matches, true) as $k => $match) {

				$kind    = $match[2][0]; // s/d/f from the first sub-pattern.
				$length  = strlen($match[0][0]); // This basic version would always be 2.
				$start   = $match[0][1];
				$removed = false;

				if ($match[1][1] > 0) { // Contains '...'

					if ($kind !== 'd' && $kind !== 's') {

						exit('Placeholders using "..." can only be used for integers (%...d) or strings (%...s)');

					} else if (!is_array($args[$k])) {

						exit('Placeholders using "..." must be provided with an array of values');

					} else {

						$replacement = join(',', array_fill(0, count($args[$k]), '%' . $kind));

						$new_args = ($new_args + array_reverse($args[$k]));

					}

				} else if ($kind === 'i' || $kind === 't') {

					if ($kind === 't') {
						if (in_array($args[$k], $this->tables, true) || in_array($args[$k], $this->global_tables, true)) {
							$identifier = $this->{$args[$k]};
						} else {
							$identifier = $this->prefix . $args[$k];
						}
					} else {
						$identifier = $args[$k];
					}

					$replacement = '`' . implode( '`.`', explode( '.' , $identifier ) ) . '`';

				} else if ($kind === 'r') {

					if ($args[$k] instanceof wpdb_sql_fragment) {

						$replacement = $args[$k];

					} else {

						exit('When using %r, the value must have come from $wpdb->prepare()');

					}

				} else {

					$replacement = $match[0][0]; // Not recognised, keep un-changed

					$replacements[$k] = false;

					$new_args[] = $args[$k];

				}

				$new_query[] = $replacement . substr($query, ($start + $length));

				$query = substr($query, 0, $start);

			}

			$new_query[] = $query;
			$new_query = array_reverse($new_query);

			$query = implode('', $new_query);
			$args = array_reverse($new_args);

		}

		$sql = parent::prepare($query, ...$args); // The following placeholders can be used in the query string: %d (integer) %f (float) %s (string)

		return new wpdb_sql_fragment($sql);

	}

	public function prepare_identifier($name) {
		$name_parts = explode( '.' , $name );
		$name       = '`' . implode( '`.`', $name_parts ) . '`';
		return new wpdb_sql_fragment($name);
	}

	public function prepare_in($values, $type = 's') {
		if (count($values) == 0) {
			// TODO: An error message of some kind?
		}
		if ($type == 'd') {
			return new wpdb_sql_fragment(implode(',', array_map('intval', $values))); // TODO: Should this use absint?
		} else if (in_array($type, ['s'])) {
			$format = implode(',', array_fill(0, count($values), '%' . $type));
			return $this->prepare($format, $values);
		}
	}

	// public function prepare_unsafe_value($sql) {
	// 	return new wpdb_sql_fragment($sql);
	// }

	public function compose_implode($glue, $fragments) {
		$this->protection_check($glue, 0);
		$this->protection_check($fragments, 1);
		if (count($fragments) == 0) {
			return ''; // Return an empty string literal, as a value-object evaluates to true.
		} else {
			return new wpdb_sql_fragment(implode($glue, $fragments));
		}
	}

	public function compose(...$fragments) {
		$this->protection_check($fragments, NULL);
		$sql = implode('', $fragments);
		if (trim($sql) === '') {
			return ''; // Return an empty string literal, as a value-object evaluates to true.
		} else {
			return new wpdb_sql_fragment($sql);
		}
	}

	public function query($query) {
		$this->protection_check($query, 0);
		return parent::query($query);
	}

}

class wpdb_sql_fragment {
	private $sql = '';
	function __construct($sql) {
		$this->sql = $sql;
	}
	function __toString() {
		return $this->sql;
	}
}

global $wpdb;
$wpdb = new wpdb_protect_class(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);

?>