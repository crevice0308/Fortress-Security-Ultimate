<?php
/**
 * Japanese admin dashboard and authenticated actions.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Admin;

use Fortress\Security\Audit\Environment;
use Fortress\Security\Audit\Inspector;
use Fortress\Security\Log\Exporter;
use Fortress\Security\Log\Logger;
use Fortress\Security\Settings;

/** Single-site administration. */
final class Dashboard {
	/**
	 * Inject only a verified private logger.
	 *
	 * @param Logger|null $logger Private logger if available.
	 */
	public function __construct( private readonly ?Logger $logger ) {}

	/** Register only authenticated routes; no nopriv/public endpoints. */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_fsu_save', array( $this, 'save' ) );
		add_action( 'admin_post_fsu_restore', array( $this, 'restore' ) );
		add_action( 'admin_post_fsu_export', array( $this, 'export' ) );
	}

	/** Add the dedicated admin menu. */
	public function menu(): void {
		add_menu_page( 'Fortress Security Ultimate', 'Fortress Security', 'manage_options', 'fortress-security-ultimate', array( $this, 'render' ), 'dashicons-shield', 80 );
	}

	/**
	 * Load a small stylesheet exclusively on this dashboard.
	 *
	 * @param string $hook WordPress admin page hook.
	 */
	public function assets( string $hook ): void {
		if ( 'toplevel_page_fortress-security-ultimate' === $hook ) {
			wp_enqueue_style( 'fsu-admin', plugins_url( 'assets/admin.css', FSU_FILE ), array(), FSU_VERSION );
		}
	}

	/** Display honest implementation status, diagnostics, settings and recovery. */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) || is_multisite() ) {
			wp_die( esc_html__( '管理者権限が必要です。', 'fortress-security-ultimate' ), '', array( 'response' => 403 ) );
		}
		$settings = Settings::get();
		$rows     = ( new Inspector() )->inspect( Environment::collect( null !== $this->logger ) );
		$stats    = null !== $this->logger ? $this->logger->stats() : array();
		?>
		<div class="wrap fsu-wrap">
			<h1>Fortress Security Ultimate <small><?php echo esc_html( FSU_VERSION ); ?></small></h1>
			<div class="notice notice-warning inline"><p><?php esc_html_e( 'Phase 1 開発版です。攻撃遮断・改ざん検知・Cloudflare・ライセンス・決済・更新配信は未実装です。販売や本番防御の検証は完了していません。', 'fortress-security-ultimate' ); ?></p></div>
			<?php if ( Settings::safe_mode() ) : ?>
				<div class="notice notice-info inline"><p><?php esc_html_e( 'セーフモード：エラー収集と定期ログ整理を停止しています。設定とログ出力は利用できます。', 'fortress-security-ultimate' ); ?></p></div>
			<?php endif; ?>
			<div class="fsu-grid">
				<section class="fsu-card"><h2><?php esc_html_e( 'セキュリティ状態', 'fortress-security-ultimate' ); ?></h2>
					<p><?php esc_html_e( '環境診断・ログ基盤：実装済み', 'fortress-security-ultimate' ); ?></p>
					<p><?php esc_html_e( '攻撃検知件数／遮断件数：計測未開始', 'fortress-security-ultimate' ); ?></p>
					<p><?php esc_html_e( 'ファイル改ざん／既知の脆弱性：未診断', 'fortress-security-ultimate' ); ?></p>
				</section>
				<section class="fsu-card"><h2><?php esc_html_e( '連携・契約', 'fortress-security-ultimate' ); ?></h2>
					<p><?php esc_html_e( 'Cloudflare：未実装・未接続', 'fortress-security-ultimate' ); ?></p>
					<p><?php esc_html_e( 'ライセンス・Stripe：未実装・課金なし', 'fortress-security-ultimate' ); ?></p>
					<p><?php esc_html_e( '月額1,890円／年額18,900円・税込・10サイト（予定）', 'fortress-security-ultimate' ); ?></p>
				</section>
			</div>
			<section class="fsu-card"><h2><?php esc_html_e( 'WordPress・PHP環境診断', 'fortress-security-ultimate' ); ?></h2>
				<p><?php esc_html_e( '設定を読み取って確認します。診断実行に外部通信はありません。', 'fortress-security-ultimate' ); ?></p>
				<div class="fsu-table-scroll"><table class="widefat striped"><thead><tr><th><?php esc_html_e( '項目', 'fortress-security-ultimate' ); ?></th><th><?php esc_html_e( '判定', 'fortress-security-ultimate' ); ?></th><th><?php esc_html_e( '説明', 'fortress-security-ultimate' ); ?></th></tr></thead><tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr><th scope="row"><?php echo esc_html( $row['title'] ); ?></th><td><?php echo esc_html( $this->status_label( $row['status'] ) ); ?></td><td><?php echo esc_html( $row['detail'] ); ?></td></tr>
				<?php endforeach; ?>
				</tbody></table></div>
			</section>
			<div class="fsu-grid">
				<section class="fsu-card"><h2><?php esc_html_e( 'ログ設定', 'fortress-security-ultimate' ); ?></h2>
					<p><?php echo null !== $this->logger ? esc_html__( '非公開保存先：利用可能', 'fortress-security-ultimate' ) : esc_html__( '非公開保存先：準備が必要です。FSU_PRIVATE_DIRの設定と権限を確認してください。', 'fortress-security-ultimate' ); ?></p>
					<p><?php esc_html_e( '1時間ごと・168時間保持・合計上限500MB。エラー本文・Cookie・パスワード・キー・IP・URLは保存しません。', 'fortress-security-ultimate' ); ?></p>
					<p><?php echo esc_html( (string) wp_json_encode( $stats ) ); ?></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="fsu_save">
						<?php wp_nonce_field( 'fsu_save' ); ?>
						<label class="fsu-control"><input type="checkbox" name="debug" value="1" <?php checked( $settings['debug'] ); ?>><?php esc_html_e( 'Debug / Traceログを有効化', 'fortress-security-ultimate' ); ?></label>
						<label class="fsu-control"><input type="checkbox" name="capture_errors" value="1" <?php checked( $settings['capture_errors'] ); ?>><?php esc_html_e( 'PHP・WordPressのエラー種別を記録', 'fortress-security-ultimate' ); ?></label>
						<fieldset><legend><?php esc_html_e( '記録カテゴリー（未実装機能のイベントは発生しません）', 'fortress-security-ultimate' ); ?></legend>
						<?php foreach ( Settings::CATEGORIES as $category ) : ?>
							<label class="fsu-control"><input type="checkbox" name="categories[]" value="<?php echo esc_attr( $category ); ?>" <?php checked( in_array( $category, $settings['categories'], true ) ); ?>><?php echo esc_html( $category ); ?></label>
						<?php endforeach; ?>
						</fieldset>
						<p><?php esc_html_e( 'internal・admin・systemの記録は維持します。', 'fortress-security-ultimate' ); ?></p>
						<?php submit_button( __( '設定を保存', 'fortress-security-ultimate' ) ); ?>
					</form>
				</section>
				<section class="fsu-card"><h2><?php esc_html_e( '解析用ZIP', 'fortress-security-ultimate' ); ?></h2>
					<p><?php esc_html_e( '再検査したJSONログ、匿名の環境情報、manifest、README、ビルド情報を含みます。出力上限は16MiBで、超過はmanifestに記録します。', 'fortress-security-ultimate' ); ?></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="fsu_export"><?php wp_nonce_field( 'fsu_export' ); ?>
						<label for="fsu-hours"><?php esc_html_e( '出力範囲', 'fortress-security-ultimate' ); ?></label>
						<select id="fsu-hours" name="hours"><option value="1"><?php esc_html_e( '直近1時間', 'fortress-security-ultimate' ); ?></option><option value="24"><?php esc_html_e( '直近24時間', 'fortress-security-ultimate' ); ?></option><option value="168"><?php esc_html_e( '過去7日間', 'fortress-security-ultimate' ); ?></option></select>
						<?php submit_button( __( 'ZIPをダウンロード', 'fortress-security-ultimate' ), 'secondary' ); ?>
					</form>
					<h2><?php esc_html_e( '緊急復旧', 'fortress-security-ultimate' ); ?></h2>
					<p><?php esc_html_e( 'サーバーのwp-config.phpでFSU_SAFE_MODEをtrueに設定すると収集を止められます。管理画面が開けない場合はプラグインのフォルダー名を変更して無効化できます。', 'fortress-security-ultimate' ); ?></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="fsu_restore"><?php wp_nonce_field( 'fsu_restore' ); ?><?php submit_button( __( '前回の設定を復元', 'fortress-security-ultimate' ), 'secondary' ); ?></form>
				</section>
			</div>
		</div>
		<?php
	}

	/** Save only allowlisted values after authorization. */
	public function save(): void {
		Access::authorize( 'save' );
		// Access::authorize verifies capability and fsu_save nonce before this input is read.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Central Access guard above.
		$input = wp_unslash( $_POST );
		Settings::save( $input );
		$this->logger?->log( 'Info', 'admin', 'settings.updated' );
		$this->redirect();
	}

	/** Roll back one bounded snapshot. */
	public function restore(): void {
		Access::authorize( 'restore' );
		Settings::restore();
		$this->logger?->log( 'Info', 'admin', 'settings.restored' );
		$this->redirect();
	}

	/** Export to a private temporary ZIP; always delete after streaming. */
	public function export(): void {
		Access::authorize( 'export' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Central Access guard above.
		$hours = isset( $_POST['hours'] ) && is_string( $_POST['hours'] ) ? sanitize_key( wp_unslash( $_POST['hours'] ) ) : '';
		if ( ! in_array( $hours, array( '1', '24', '168' ), true ) || null === $this->logger || headers_sent() ) {
			wp_die( esc_html__( 'ログ保存先・ZIP拡張・出力範囲を確認してください。', 'fortress-security-ultimate' ), '', array( 'response' => 400 ) );
		}
		$path = null;
		try {
			$environment                      = Environment::collect( true );
			$environment['version']           = FSU_VERSION;
			$environment['channel']           = 'dev';
			$environment['wordpress_version'] = $environment['wp_version'];
			$build_file                       = FSU_DIR . 'build-info.json';
			if ( is_file( $build_file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- Bounded local build metadata; a missing/unreadable file must not expose a path.
				$build                 = json_decode( (string) @file_get_contents( $build_file, false, null, 0, 4096 ), true );
				$environment['commit'] = is_array( $build ) && isset( $build['git_commit'] ) && is_string( $build['git_commit'] ) ? $build['git_commit'] : 'unknown';
			}
			$path     = ( new Exporter( $this->logger ) )->build( (int) $hours, $environment );
			$download = ZipDownload::open( $path );
		} catch ( \Throwable $error ) {
			ZipDownload::cleanup( null, $path );
			wp_die( esc_html__( 'ZIPを作成できませんでした。保存先の権限・空き容量・zip拡張を確認してください。', 'fortress-security-ultimate' ), '', array( 'response' => 500 ) );
		}
		try {
			nocache_headers();
			header( 'Content-Type: application/zip' );
			header( 'Content-Disposition: attachment; filename="fsu-logs-' . (int) $hours . 'h.zip"' );
			header( 'Content-Length: ' . $download['size'] );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'Cache-Control: private, no-store, max-age=0' );
			if ( ZipDownload::send( $download['stream'], $download['size'] ) ) {
				$this->logger->log( 'Info', 'admin', 'logs.exported', array( 'range_hours' => (int) $hours ) );
			} else {
				$this->logger->log( 'Error', 'internal', 'internal.error' );
			}
		} finally {
			ZipDownload::cleanup( $download['stream'], $path );
		}
		exit;
	}

	/**
	 * Translate finite result labels.
	 *
	 * @param string $status Finite diagnostic result.
	 */
	private function status_label( string $status ): string {
		$labels = array(
			'pass'    => __( '確認済', 'fortress-security-ultimate' ),
			'warning' => __( '要確認', 'fortress-security-ultimate' ),
			'error'   => __( '対応が必要', 'fortress-security-ultimate' ),
			'info'    => __( '情報／未判定', 'fortress-security-ultimate' ),
		);
		return $labels[ $status ] ?? $labels['info'];
	}

	/** Fixed same-site redirect. */
	private function redirect(): void {
		wp_safe_redirect( admin_url( 'admin.php?page=fortress-security-ultimate' ) );
		exit;
	}
}
