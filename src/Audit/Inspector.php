<?php
/**
 * Pure, read-only environment checks.
 *
 * @package FortressSecurityUltimate
 */

namespace Fortress\Security\Audit;

/**
 * Interprets a deliberately small environment snapshot without I/O.
 *
 * These checks do not establish that a PHP or WordPress installation has no CVEs.
 */
final class Inspector {

	/**
	 * Build diagnostic rows; missing or malformed values remain unknown.
	 *
	 * @param array<string,mixed> $environment Non-sensitive environment metadata.
	 * @return list<array{id:string,status:string,title:string,detail:string}>
	 */
	public function inspect( array $environment ): array {
		$rows   = array();
		$rows[] = $this->php_version( $environment['php_version'] ?? null );
		$rows[] = $this->wordpress_version( $environment['wp_version'] ?? null );

		$checks = array(
			'https'              => array( 'HTTPS', true, 'HTTPS接続を確認しました。', 'HTTPS接続を確認できません。信頼するプロキシのHTTPS設定も確認してください。', 'warning' ),
			'debug_display'      => array( 'WordPressデバッグ表示', false, 'WordPressのデバッグ表示は無効です。', 'WordPressのデバッグ表示が有効です。画面に内部情報を出さない設定にしてください。', 'warning' ),
			'file_edit_disabled' => array( '管理画面のファイル編集', true, '管理画面からのテーマ・プラグイン編集は無効です。', '管理画面からのファイル編集を無効にする設定を検討してください。', 'warning' ),
			'expose_php'         => array( 'PHP情報ヘッダー', false, 'expose_phpは無効です。', 'expose_phpが有効です。PHPの種類を示すヘッダーを抑制する設定を検討してください。', 'warning' ),
			'display_errors'     => array( 'PHPエラー表示', false, 'PHPエラーの画面表示は無効です。', 'PHPエラーの画面表示が有効です。内部情報が表示される場合があります。', 'warning' ),
			'allow_url_include'  => array( '外部URLのPHP読み込み', false, 'allow_url_includeは無効です。', 'allow_url_includeが有効です。サーバー設定で無効にしてください。', 'error' ),
			'zip_available'      => array( 'ログZIP出力', true, 'ZipArchiveを利用できます。', 'ZipArchiveを利用できません。ログZIP出力にはPHPのzip拡張が必要です。', 'warning' ),
			'logs_ready'         => array( '非公開ログ保存', true, '非公開ログ保存先を利用できます。', '非公開ログ保存先の準備が必要です。保存先とアクセス権限を確認してください。', 'warning' ),
		);

		foreach ( $checks as $key => $check ) {
			$value = $environment[ $key ] ?? null;
			if ( ! is_bool( $value ) ) {
				$rows[] = $this->row( $key, 'info', $check[0], '設定値を取得できないため、判定を保留しています。' );
				continue;
			}
			$pass   = $value === $check[1];
			$rows[] = $this->row( $key, $pass ? 'pass' : $check[4], $check[0], $pass ? $check[2] : $check[3] );
		}

		$rows[] = $this->permissions( 'config_permissions', '設定ファイルの権限', $environment['config_permissions'] ?? null, true );
		$rows[] = $this->permissions( 'content_permissions', 'コンテンツ保存先の権限', $environment['content_permissions'] ?? null, false );

		$extensions = $environment['extensions'] ?? array();
		$extensions = is_array( $extensions ) ? $extensions : array();
		foreach ( array( 'json', 'openssl', 'sodium' ) as $name ) {
			$value  = $extensions[ $name ] ?? null;
			$rows[] = $this->row(
				'extension_' . $name,
				is_bool( $value ) ? ( $value ? 'pass' : 'warning' ) : 'info',
				'PHP拡張: ' . $name,
				is_bool( $value ) ? ( $value ? '拡張を利用できます。' : '拡張を利用できません。対応する将来機能の動作条件を確認してください。' ) : '拡張の利用可否を取得できません。'
			);
		}

		$rows[] = $this->row( 'audit_scope', 'info', '診断の範囲', '環境設定の読み取り専用診断です。既知の脆弱性照合、コア整合性検証、改ざん検知はこの開発段階では未実装です。' );
		return $rows;
	}

	/**
	 * Check against the recorded support policy, not a vulnerability database.
	 *
	 * @param mixed $value PHP version.
	 * @return array{id:string,status:string,title:string,detail:string}
	 */
	private function php_version( $value ): array {
		$version = $this->version( $value );
		if ( null === $version ) {
			return $this->row( 'php_version', 'info', 'PHPバージョン', 'バージョンを取得できません。' );
		}
		if ( is_string( $value ) && preg_match( '/(?:alpha|beta|rc|dev)/i', $value ) ) {
			return $this->row( 'php_version', 'info', 'PHPバージョン', '開発版またはリリース候補のPHPです。正式版と同じサポート判定は行いません。' );
		}
		if ( version_compare( $version, '8.2', '<' ) ) {
			return $this->row( 'php_version', 'error', 'PHPバージョン', 'この開発版の対象はPHP 8.2〜8.5です。サポート中のPHPへの更新を確認してください。' );
		}
		if ( version_compare( $version, '8.3', '<' ) ) {
			return $this->row( 'php_version', 'warning', 'PHPバージョン', 'PHP 8.2系です。2026年11月3日時点の方針ではセキュリティサポート終了は2026年12月31日です。更新を計画してください。パッチ単位の脆弱性照合は未実装です。' );
		}
		if ( version_compare( $version, '8.6', '>=' ) ) {
			return $this->row( 'php_version', 'info', 'PHPバージョン', 'PHP 8.2〜8.5の開発対象範囲を超えています。互換性は未検証です。' );
		}
		return $this->row( 'php_version', 'pass', 'PHPバージョン', 'PHP 8.3〜8.5の開発対象範囲です。パッチ単位の脆弱性照合や、この環境での互換性保証を意味しません。' );
	}

	/**
	 * Check the development target without treating it as a CVE verdict.
	 *
	 * @param mixed $value WordPress version.
	 * @return array{id:string,status:string,title:string,detail:string}
	 */
	private function wordpress_version( $value ): array {
		$version = $this->version( $value );
		if ( null === $version ) {
			return $this->row( 'wp_version', 'info', 'WordPressバージョン', 'バージョンを取得できません。' );
		}
		if ( is_string( $value ) && preg_match( '/(?:alpha|beta|rc|dev)/i', $value ) ) {
			return $this->row( 'wp_version', 'info', 'WordPressバージョン', '開発版またはリリース候補のWordPressです。正式版と同じ互換性判定は行いません。' );
		}
		if ( version_compare( $version, '7.1', '<' ) ) {
			return $this->row( 'wp_version', 'warning', 'WordPressバージョン', 'この開発版の検証対象はWordPress 7.1系です。公式の更新情報を確認してください。既知の脆弱性照合は未実装です。' );
		}
		if ( version_compare( $version, '7.2', '>=' ) ) {
			return $this->row( 'wp_version', 'info', 'WordPressバージョン', 'WordPress 7.1系より新しいバージョンです。互換性は未検証です。' );
		}
		return $this->row( 'wp_version', 'pass', 'WordPressバージョン', 'WordPress 7.1系の開発対象範囲です。コアファイルの整合性や脆弱性の有無を判定した結果ではありません。' );
	}

	/**
	 * Normalize only a conventional numeric version and optional release suffix.
	 *
	 * @param mixed $value Untrusted version value.
	 * @return string|null
	 */
	private function version( $value ): ?string {
		if ( ! is_string( $value ) || strlen( $value ) > 80 || ! preg_match( '/\A(\d{1,3}\.\d{1,3}(?:\.\d{1,3})?)(?:[-+._a-zA-Z0-9]*)\z/D', $value, $match ) ) {
			return null;
		}
		return $match[1];
	}

	/**
	 * Inspect Unix permission bits without changing them.
	 *
	 * @param string $id Check identifier.
	 * @param string $title Human label.
	 * @param mixed  $value Unix permission bits, already masked to 07777.
	 * @param bool   $secret Whether the file holds secrets.
	 * @return array{id:string,status:string,title:string,detail:string}
	 */
	private function permissions( string $id, string $title, $value, bool $secret ): array {
		if ( ! is_int( $value ) || $value < 0 || $value > 07777 ) {
			return $this->row( $id, 'info', $title, '権限を取得できません。Windowsやアクセス制御リストを使う環境はサーバー側でも確認してください。' );
		}
		if ( 0 !== ( $value & 0002 ) ) {
			return $this->row( $id, 'error', $title, 'すべてのローカルユーザーに書き込み権限があります。サーバー管理者と権限を確認してください。' );
		}
		if ( 0 !== ( $value & 07020 ) || ( $secret && 0 !== ( $value & 0007 ) ) ) {
			return $this->row( $id, 'warning', $title, '共有ユーザーへの権限または特殊権限を確認してください。実行ユーザーと必要な権限はサーバー構成によって異なります。' );
		}
		return $this->row( $id, 'pass', $title, '確認したUnix権限ビットに全ユーザーの書き込み権限はありません。所有者やアクセス制御リストは別途確認してください。' );
	}

	/**
	 * Construct a serializable row containing no environment identifiers.
	 *
	 * @param string $id Stable check identifier.
	 * @param string $status pass, warning, info or error.
	 * @param string $title Japanese title.
	 * @param string $detail Japanese explanation.
	 * @return array{id:string,status:string,title:string,detail:string}
	 */
	private function row( string $id, string $status, string $title, string $detail ): array {
		return array(
			'id'     => $id,
			'status' => $status,
			'title'  => $title,
			'detail' => $detail,
		);
	}
}
