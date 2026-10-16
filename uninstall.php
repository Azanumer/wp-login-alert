<?php
/**
 * Uninstall cleanup for WP Login Alert.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wla_logins' );
delete_option( 'wla_settings' );
wp_clear_scheduled_hook( 'wla_daily_cleanup' );

// Remove per-user known-IP lists.
$users = get_users( array( 'meta_key' => 'wla_known_ips', 'fields' => 'ID' ) );
foreach ( $users as $uid ) {
    delete_user_meta( $uid, 'wla_known_ips' );
}
