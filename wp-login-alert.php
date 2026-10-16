<?php
/**
 * Plugin Name: WP Login Alert
 * Description: Emails you when a privileged account logs in from a new IP — early warning for compromised accounts. Keeps a paged login log under Tools.
 * Version:     1.0.0
 * Author:      Azan Umer
 * License:     MIT
 * License URI: https://opensource.org/licenses/MIT
 * Text Domain: wp-login-alert
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WLA_VERSION', '1.0.0' );
define( 'WLA_OPTION', 'wla_settings' );
define( 'WLA_META', 'wla_known_ips' ); // user meta: array( ip => timestamp )

/**
 * Settings with defaults.
 *
 * @return array
 */
function wla_get_settings() {
    $defaults = array(
        'monitored_roles'   => array( 'administrator' ),
        'alert_email'       => '',   // empty = site admin_email
        'known_ip_days'     => 90,   // a "known" IP expires after this many days
        'log_retention'     => 90,   // login-log rows kept this many days
        'max_known_ips'     => 20,   // cap per user, oldest pruned first
    );
    $saved = get_option( WLA_OPTION, array() );
    return wp_parse_args( is_array( $saved ) ? $saved : array(), $defaults );
}

/**
 * Best-effort client IP. Filterable for sites behind a trusted proxy.
 *
 * @return string
 */
function wla_client_ip() {
    $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
    return apply_filters( 'wla_client_ip', $ip );
}

/**
 * Table name for the login log.
 *
 * @return string
 */
function wla_table() {
    global $wpdb;
    return $wpdb->prefix . 'wla_logins';
}

function wla_activate() {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $table   = wla_table();
    $charset = $wpdb->get_charset_collate();
    $sql     = "CREATE TABLE $table (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        user_id bigint(20) unsigned NOT NULL,
        user_login varchar(60) NOT NULL,
        ip varchar(45) NOT NULL,
        user_agent varchar(255) NOT NULL DEFAULT '',
        created_at datetime NOT NULL,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY created_at (created_at)
    ) $charset;";
    dbDelta( $sql );
    if ( ! wp_next_scheduled( 'wla_daily_cleanup' ) ) {
        wp_schedule_event( time(), 'daily', 'wla_daily_cleanup' );
    }
}
register_activation_hook( __FILE__, 'wla_activate' );

function wla_deactivate() {
    wp_clear_scheduled_hook( 'wla_daily_cleanup' );
}
register_deactivation_hook( __FILE__, 'wla_deactivate' );

/**
 * Daily cleanup: prune old login rows and expired known IPs.
 */
function wla_daily_cleanup() {
    global $wpdb;
    $settings = wla_get_settings();
    $days     = max( 1, (int) $settings['log_retention'] );
    $wpdb->query( $wpdb->prepare(
        'DELETE FROM ' . wla_table() . ' WHERE created_at < %s',
        gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS )
    ) );
    $known_days = max( 1, (int) $settings['known_ip_days'] );
    $cutoff     = time() - $known_days * DAY_IN_SECONDS;
    foreach ( get_users( array( 'meta_key' => WLA_META, 'fields' => 'ID' ) ) as $uid ) {
        $known = get_user_meta( $uid, WLA_META, true );
        if ( ! is_array( $known ) ) {
            continue;
        }
        $kept = array_filter( $known, function ( $ts ) use ( $cutoff ) {
            return $ts >= $cutoff;
        } );
        if ( $kept !== $known ) {
            update_user_meta( $uid, WLA_META, $kept );
        }
    }
}
add_action( 'wla_daily_cleanup', 'wla_daily_cleanup' );

/**
 * Send the "new IP login" alert mail.
 */
function wla_send_alert( $user, $ip, $is_new_ip ) {
    $settings = wla_get_settings();
    $to       = $settings['alert_email'] ? $settings['alert_email'] : get_option( 'admin_email' );
    $site     = get_bloginfo( 'name' );
    $rdns     = gethostbyaddr( $ip );
    $ua       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
    $when     = current_time( 'Y-m-d H:i:s' );

    // translators: 1: site name, 2: user login.
    $subject = sprintf( __( '[%1$s] Login alert: %2$s', 'wp-login-alert' ), $site, $user->user_login );
    if ( $is_new_ip ) {
        // translators: 1: site name, 2: user login.
        $subject = sprintf( __( '[%1$s] NEW IP login: %2$s', 'wp-login-alert' ), $site, $user->user_login );
    }

    $message  = sprintf( __( "Account: %s (%s)\n", 'wp-login-alert' ), $user->user_login, implode( ', ', $user->roles ) );
    $message .= sprintf( __( "IP:      %s\n", 'wp-login-alert' ), $ip );
    if ( $rdns && $rdns !== $ip ) {
        $message .= sprintf( __( "rDNS:    %s\n", 'wp-login-alert' ), $rdns );
    }
    $message .= sprintf( __( "When:    %s\n", 'wp-login-alert' ), $when );
    $message .= sprintf( __( "Browser: %s\n", 'wp-login-alert' ), $ua );
    $message .= "\n" . __( "If this was not you, change the password immediately and check the login log under Tools → Login Log.", 'wp-login-alert' ) . "\n";

    wp_mail( $to, $subject, $message );
}

/**
 * Log every successful login; alert when a monitored role logs in from a new IP.
 */
function wla_on_login( $user_login, $user ) {
    global $wpdb;
    $settings = wla_get_settings();
    $ip       = wla_client_ip();
    $ua       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ), 0, 255 ) : '';

    $wpdb->insert(
        wla_table(),
        array(
            'user_id'    => $user->ID,
            'user_login' => $user->user_login,
            'ip'         => $ip,
            'user_agent' => $ua,
            'created_at' => current_time( 'mysql' ),
        ),
        array( '%d', '%s', '%s', '%s', '%s' )
    );

    // Alert only for monitored roles.
    if ( empty( array_intersect( (array) $user->roles, (array) $settings['monitored_roles'] ) ) ) {
        return;
    }

    $known     = get_user_meta( $user->ID, WLA_META, true );
    $known     = is_array( $known ) ? $known : array();
    $cutoff    = time() - max( 1, (int) $settings['known_ip_days'] ) * DAY_IN_SECONDS;
    $known     = array_filter( $known, function ( $ts ) use ( $cutoff ) {
        return $ts >= $cutoff;
    } );
    $is_new_ip = ! isset( $known[ $ip ] );

    wla_send_alert( $user, $ip, $is_new_ip );

    // Remember this IP (cap the list, oldest first).
    $known[ $ip ] = time();
    $max          = max( 1, (int) $settings['max_known_ips'] );
    if ( count( $known ) > $max ) {
        asort( $known );
        $known = array_slice( $known, -$max, $max, true );
    }
    update_user_meta( $user->ID, WLA_META, $known );
}
add_action( 'wp_login', 'wla_on_login', 10, 2 );

// --- Settings page: Settings → Login Alert -----------------------------------

function wla_register_settings() {
    register_setting( 'wla_settings_group', WLA_OPTION, 'wla_sanitize_settings' );
}
add_action( 'admin_init', 'wla_register_settings' );

function wla_sanitize_settings( $input ) {
    $out = array();
    $roles = array();
    if ( ! empty( $input['monitored_roles'] ) && is_array( $input['monitored_roles'] ) ) {
        $editable = array_keys( get_editable_roles() );
        foreach ( $input['monitored_roles'] as $role ) {
            $role = sanitize_key( $role );
            if ( in_array( $role, $editable, true ) ) {
                $roles[] = $role;
            }
        }
    }
    $out['monitored_roles'] = $roles;
    $out['alert_email']     = isset( $input['alert_email'] ) ? sanitize_email( $input['alert_email'] ) : '';
    $out['known_ip_days']   = isset( $input['known_ip_days'] ) ? max( 1, absint( $input['known_ip_days'] ) ) : 90;
    $out['log_retention']   = isset( $input['log_retention'] ) ? max( 1, absint( $input['log_retention'] ) ) : 90;
    $out['max_known_ips']   = isset( $input['max_known_ips'] ) ? max( 1, absint( $input['max_known_ips'] ) ) : 20;
    return $out;
}

function wla_settings_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $settings = wla_get_settings();
    $roles    = get_editable_roles();
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Login Alert', 'wp-login-alert' ); ?></h1>
        <form method="post" action="options.php">
            <?php settings_fields( 'wla_settings_group' ); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Monitored roles', 'wp-login-alert' ); ?></th>
                    <td>
                        <?php foreach ( $roles as $slug => $role ) : ?>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr( WLA_OPTION ); ?>[monitored_roles][]"
                                    value="<?php echo esc_attr( $slug ); ?>"
                                    <?php checked( in_array( $slug, (array) $settings['monitored_roles'], true ) ); ?> />
                                <?php echo esc_html( translate_user_role( $role['name'] ) ); ?>
                            </label><br />
                        <?php endforeach; ?>
                        <p class="description"><?php esc_html_e( 'An email is sent every time one of these roles logs in. "NEW IP" is flagged when the IP is not in the known list.', 'wp-login-alert' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Alert email', 'wp-login-alert' ); ?></th>
                    <td>
                        <input type="email" class="regular-text" name="<?php echo esc_attr( WLA_OPTION ); ?>[alert_email]"
                            value="<?php echo esc_attr( $settings['alert_email'] ); ?>"
                            placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
                        <p class="description"><?php esc_html_e( 'Empty = site admin email.', 'wp-login-alert' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Known IP lifetime (days)', 'wp-login-alert' ); ?></th>
                    <td><input type="number" min="1" name="<?php echo esc_attr( WLA_OPTION ); ?>[known_ip_days]"
                        value="<?php echo esc_attr( $settings['known_ip_days'] ); ?>" /></td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Login log retention (days)', 'wp-login-alert' ); ?></th>
                    <td><input type="number" min="1" name="<?php echo esc_attr( WLA_OPTION ); ?>[log_retention]"
                        value="<?php echo esc_attr( $settings['log_retention'] ); ?>" /></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

function wla_admin_menu() {
    add_options_page(
        __( 'Login Alert', 'wp-login-alert' ),
        __( 'Login Alert', 'wp-login-alert' ),
        'manage_options',
        'wla-settings',
        'wla_settings_page'
    );
    add_management_page(
        __( 'Login Log', 'wp-login-alert' ),
        __( 'Login Log', 'wp-login-alert' ),
        'manage_options',
        'wla-log',
        'wla_log_page'
    );
}
add_action( 'admin_menu', 'wla_admin_menu' );

// --- Tools → Login Log ---------------------------------------------------------

function wla_log_page() {
    global $wpdb;
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( isset( $_POST['wla_clear'] ) && check_admin_referer( 'wla_clear_log' ) ) {
        $wpdb->query( 'TRUNCATE TABLE ' . wla_table() );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'Login log cleared.', 'wp-login-alert' ) . '</p></div>';
    }

    $per_page = 20;
    $page     = max( 1, isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1 );
    $offset   = ( $page - 1 ) * $per_page;
    $total    = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . wla_table() );
    $rows     = $wpdb->get_results( $wpdb->prepare(
        'SELECT * FROM ' . wla_table() . ' ORDER BY created_at DESC LIMIT %d OFFSET %d',
        $per_page, $offset
    ) );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Login Log', 'wp-login-alert' ); ?></h1>
        <form method="post" style="margin-bottom:12px">
            <?php wp_nonce_field( 'wla_clear_log' ); ?>
            <input type="submit" name="wla_clear" class="button button-secondary"
                value="<?php esc_attr_e( 'Clear log', 'wp-login-alert' ); ?>"
                onclick="return confirm('<?php esc_attr_e( 'Delete all login log entries?', 'wp-login-alert' ); ?>')" />
        </form>
        <table class="widefat striped">
            <thead><tr>
                <th><?php esc_html_e( 'When', 'wp-login-alert' ); ?></th>
                <th><?php esc_html_e( 'User', 'wp-login-alert' ); ?></th>
                <th><?php esc_html_e( 'IP', 'wp-login-alert' ); ?></th>
                <th><?php esc_html_e( 'Browser', 'wp-login-alert' ); ?></th>
            </tr></thead>
            <tbody>
                <?php if ( $rows ) : foreach ( $rows as $row ) : ?>
                    <tr>
                        <td><?php echo esc_html( $row->created_at ); ?></td>
                        <td><?php echo esc_html( $row->user_login ); ?></td>
                        <td><?php echo esc_html( $row->ip ); ?></td>
                        <td><?php echo esc_html( mb_substr( $row->user_agent, 0, 80 ) ); ?></td>
                    </tr>
                <?php endforeach; else : ?>
                    <tr><td colspan="4"><?php esc_html_e( 'No logins recorded yet.', 'wp-login-alert' ); ?></td></tr>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
        $pages = (int) ceil( $total / $per_page );
        if ( $pages > 1 ) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            echo paginate_links( array(
                'base'    => add_query_arg( 'paged', '%#%' ),
                'format'  => '',
                'current' => $page,
                'total'   => $pages,
            ) );
            echo '</div></div>';
        }
        ?>
    </div>
    <?php
}
