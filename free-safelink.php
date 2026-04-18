<?php
/**
 * Plugin Name: The Plotline Safelink
 * Plugin URI:  https://theplotlinee.link
 * Description: Multi-step link redirect with timer + scroll-gate, AdSense slots, anti-adblock, bot API.
 * Version:     8.0.0 (Full Rebuild — Scroll+Timer Gate, Mobile Fixed)
 * Author:      Akash Shibu
 * Author URI:  https://theplotlinee.link
 * License:     GPL v2 or later
 *
 * WHAT CHANGED vs 7.2.0
 * ─────────────────────
 * FIX-1  Button never enabled  → was driven by CSS `pointer-events:none` with no JS removal;
 *         now button starts `disabled` (HTML attr) + JS removes attr + pointer-events on enable.
 * FIX-2  Scroll gate missing   → added real scroll detection; button enables ONLY after
 *         BOTH timer AND scroll are satisfied.
 * FIX-3  Mobile click lost     → touchstart/touchend/click triple-guard kept; gone-flag
 *         prevents double-fire. Added passive:false + preventDefault on touch.
 * FIX-4  Step-skip bypass      → server validates step token (HMAC); direct jump to step=2
 *         or step=3 without completing step=1 is rejected with 403.
 * FIX-5  BFCache stale page    → added pageshow/pagehide listeners; force-reload on BFCache.
 * FIX-6  Ad z-index overlap    → fsl-ad-wrap z-index:0, button bar z-index:9999 (hard).
 * FIX-7  Samsung Internet bug  → translateZ(0) + will-change:transform on button.
 * FIX-8  Cloudflare HTTPS loop → server-side HTTPS detection + 301 upgrade before render.
 */

if (!defined('ABSPATH')) exit;

define('FSL_PUB',     'ca-pub-3342343098210473');
define('FSL_VER',     '8.0.0');
define('FSL_SALT',    'fsl_hmac_salt_v8');   // change per install in production

// ══════════════════════════════════════════════════════════════════════════════
// HTTPS ENFORCEMENT (fixes Cloudflare Flexible SSL + Android mixed-content)
// ══════════════════════════════════════════════════════════════════════════════
add_filter('home_url', fn($url) => str_replace('http://', 'https://', $url), 1);

if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}
if (!empty($_SERVER['HTTP_CF_VISITOR'])) {
    $cf = json_decode($_SERVER['HTTP_CF_VISITOR'], true);
    if (!empty($cf['scheme']) && $cf['scheme'] === 'https') $_SERVER['HTTPS'] = 'on';
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS — HTTPS detection, token, URL
// ══════════════════════════════════════════════════════════════════════════════
function fsl_is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        || (!empty($_SERVER['HTTP_CF_VISITOR'])         && str_contains($_SERVER['HTTP_CF_VISITOR'], '"https"'))
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
}

/** Generate step-advance HMAC token — prevents skipping steps */
function fsl_token(string $code, int $to_step): string {
    $key = wp_salt('auth') . FSL_SALT;
    return substr(hash_hmac('sha256', "$code:$to_step", $key), 0, 16);
}

function fsl_verify_token(string $code, int $step, string $tok): bool {
    return hash_equals(fsl_token($code, $step), $tok);
}

function fsl_url(string $code): string {
    return 'https://' . $_SERVER['HTTP_HOST'] . '/?fsl=' . rawurlencode($code);
}

/** Build URL for next step, signed with HMAC token */
function fsl_step_url(string $code, int $step): string {
    $tok = fsl_token($code, $step);
    return 'https://' . $_SERVER['HTTP_HOST']
         . '/?fsl=' . rawurlencode($code)
         . '&step=' . $step
         . '&tok='  . rawurlencode($tok);
}

// ══════════════════════════════════════════════════════════════════════════════
// STORAGE
// ══════════════════════════════════════════════════════════════════════════════
function fsl_save(string $url): string|false {
    $url = trim($url);
    if (empty($url) || !preg_match('/^https?:\/\//i', $url)) return false;
    $index = get_option('fsl_url_index', []);
    if (isset($index[$url])) return $index[$url];
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    do {
        $code = '';
        for ($i = 0; $i < 8; $i++) $code .= $chars[random_int(0, 61)];
    } while (get_option('fsl_link_' . $code));
    update_option('fsl_link_' . $code, ['url' => $url, 'views' => 0, 'clicks' => 0, 'date' => date('Y-m-d H:i:s')], false);
    $index[$url] = $code;
    update_option('fsl_url_index', $index, false);
    return $code;
}

function fsl_get(string $code): array|false {
    $code = sanitize_text_field($code);
    $d = get_option('fsl_link_' . $code);
    if (!$d || empty($d['url'])) return false;
    if (!preg_match('/^https?:\/\//i', $d['url'])) {
        $d['url'] = 'https://' . $d['url'];
        update_option('fsl_link_' . $code, $d, false);
    }
    return $d;
}

function fsl_track(string $code, string $type): void {
    $d = fsl_get($code);
    if (!$d) return;
    $d[$type] = (int)($d[$type] ?? 0) + 1;
    update_option('fsl_link_' . $code, $d, false);
}

function fsl_delete(string $code): void {
    $d = fsl_get($code);
    if ($d) {
        $i = get_option('fsl_url_index', []);
        unset($i[$d['url']]);
        update_option('fsl_url_index', $i, false);
    }
    delete_option('fsl_link_' . $code);
}

function fsl_all(): array {
    global $wpdb;
    $rows = $wpdb->get_results(
        "SELECT option_name,option_value FROM {$wpdb->options}
         WHERE option_name LIKE 'fsl_link_%' AND option_name!='fsl_link_'
         ORDER BY option_id DESC"
    );
    $out = [];
    foreach ($rows as $r) {
        $code = str_replace('fsl_link_', '', $r->option_name);
        if (strlen($code) === 8) {
            $d = maybe_unserialize($r->option_value);
            if (is_array($d)) $out[$code] = $d;
        }
    }
    return $out;
}

function fsl_opts(): array {
    return wp_parse_args(get_option('fsl_options', []), [
        'step1_title'  => '🎬 Your file is waiting!',
        'step1_sub'    => 'Read the page and scroll down — then click Continue',
        'step1_btn'    => 'Continue to Get Your File →',
        'step2_title'  => '✅ Almost there!',
        'step2_sub'    => 'Scroll down and wait — then click to get your file',
        'step2_btn'    => 'Get My File Now →',
        'countdown1'   => 10,
        'countdown2'   => 7,
        'api_key'      => '',
        'anti_adblock' => '1',
        'adb_title'    => 'Please Disable AdBlock',
        'adb_msg'      => 'We rely on ads to keep content free. Please whitelist theplotlinee.link',
        'slot_s1_top'  => '',
        'slot_s1_mid'  => '',
        'slot_s1_bot'  => '',
        'slot_s2_top'  => '',
        'slot_s2_mid'  => '',
        'slot_s2_bot'  => '',
    ]);
}

// ══════════════════════════════════════════════════════════════════════════════
// REQUEST HANDLER
// ══════════════════════════════════════════════════════════════════════════════
add_action('template_redirect', function () {
    $code = sanitize_text_field($_GET['fsl'] ?? get_query_var('fsl_code', ''));
    if (empty($code)) return;

    // Enforce HTTPS (Android fix)
    if (!fsl_is_https()) {
        header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], true, 301);
        exit;
    }

    $data = fsl_get($code);
    if (!$data || empty($data['url'])) {
        wp_die('Link not found or expired.', 'Invalid Link', ['response' => 404]);
    }

    $step = max(1, min(3, (int)($_GET['step'] ?? 1)));

    // ── STEP-SKIP PREVENTION ──────────────────────────────────────
    // Step 1 needs no token (entry point). Steps 2 & 3 require a valid HMAC.
    if ($step >= 2) {
        $tok = sanitize_text_field($_GET['tok'] ?? '');
        if (!fsl_verify_token($code, $step, $tok)) {
            wp_die('Session expired. Please <a href="' . esc_url(fsl_url($code)) . '">start over</a>.', 'Access Denied', ['response' => 403]);
        }
    }

    fsl_track($code, 'views');

    // ── STEP 3: final redirect ────────────────────────────────────
    if ($step === 3) {
        fsl_track($code, 'clicks');
        $dest = $data['url'];

        // ── URL VALIDATION ──────────────────────────────────────────
        // DO NOT use FILTER_VALIDATE_URL — rejects t.me and tg:// links.
        // DO NOT use esc_url() on the dest — it strips non-http schemes.
        // Use raw parse_url + scheme whitelist only.
        $parsed = parse_url($dest);
        $scheme = strtolower($parsed['scheme'] ?? '');
        $host   = strtolower($parsed['host']   ?? '');

        $valid = (($scheme === 'http' || $scheme === 'https') && !empty($host))
              || ($scheme === 'tg'); // tg://resolve?domain=...

        if (!$valid) {
            wp_die('Destination URL is invalid.', 'Redirect Error', ['response' => 400]);
        }

        // Wipe any output WordPress may have buffered already
        while (ob_get_level()) ob_end_clean();

        // Kill any WP session cookies being set (they trigger output)
        header_remove('Set-Cookie');

        // No-cache for all paths
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');

        // ── Is this a Telegram destination? ────────────────────────
        // Covers: https://t.me/*, https://*.t.me/*, tg://*
        $is_telegram = ($host === 't.me')
                    || str_ends_with($host, '.t.me')
                    || ($scheme === 'tg');

        if ($is_telegram) {
            // ── TELEGRAM HTML REDIRECT PAGE ─────────────────────────
            // A bare Location: header to t.me opens the browser, not
            // the Telegram app on Android. The only reliable way is an
            // <a> element that the USER or JS clicks — browsers treat
            // that as a trusted navigation and pass it to the OS intent
            // system, which opens the Telegram app.
            //
            // We use htmlspecialchars() (NOT esc_url) so the URL is
            // safe for an HTML attribute but NOT stripped of tg:// etc.
            $attr_url = htmlspecialchars($dest, ENT_QUOTES, 'UTF-8');
            $js_url   = json_encode($dest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            header('Content-Type: text/html; charset=UTF-8');
            echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Opening Telegram…</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#e8f4fd;min-height:100vh;display:flex;
     align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:20px;padding:36px 28px;
      text-align:center;max-width:340px;width:100%;
      box-shadow:0 8px 32px rgba(0,136,204,.15)}
.icon{font-size:56px;line-height:1;margin-bottom:16px}
h1{font-size:20px;font-weight:800;color:#111;margin-bottom:8px}
p{font-size:14px;color:#666;line-height:1.6;margin-bottom:24px}
.bar{height:4px;background:#e0e0e0;border-radius:99px;
     margin-bottom:24px;overflow:hidden}
.bar-fill{height:100%;width:0%;background:#0088cc;
          border-radius:99px;animation:prog 1.5s ease forwards}
@keyframes prog{to{width:100%}}
a.tg-btn{
  display:block;background:#0088cc;color:#fff;
  text-decoration:none;padding:16px 24px;border-radius:14px;
  font-size:16px;font-weight:800;letter-spacing:.3px;
  -webkit-tap-highlight-color:transparent;
  touch-action:manipulation;
}
a.tg-btn:active{opacity:.85}
.note{font-size:11px;color:#aaa;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="icon">✈️</div>
  <h1>Opening Telegram…</h1>
  <p>Your file is ready. Tap the button below to open it in Telegram.</p>
  <div class="bar"><div class="bar-fill"></div></div>
  <a class="tg-btn" id="tgBtn" href="{$attr_url}" rel="nofollow noreferrer">
    Open in Telegram
  </a>
  <p class="note">If nothing happens, tap the button above.</p>
</div>
<script>
(function(){
  var url = {$js_url};
  var btn = document.getElementById('tgBtn');

  // Android blocks auto location.href for deep links (tg://) from non-user-gesture context.
  // The only reliable method on Android is a real <a href> click from within a user gesture.
  // We attempt location.href only for https:// t.me links where Android may allow it.
  if (url.indexOf('tg://') === -1) {
    // Standard HTTPS t.me link: location.href works on most Android browsers
    try { window.location.href = url; } catch(e){}
  }

  // Programmatic anchor click at 600ms — treated as user-initiated on most Android Chrome builds
  // when the page has just loaded and no other gesture-blocking policy is active.
  setTimeout(function(){
    try { if(btn){ btn.click(); } } catch(e){}
  }, 600);

  // Final fallback via location.replace at 1.8s
  setTimeout(function(){
    try { window.location.replace(url); } catch(e){}
  }, 1800);
})();
</script>
</body>
</html>
HTML;
            exit;
        }

        // ── Standard HTTP/HTTPS redirect ────────────────────────────
        header('Location: ' . $dest, true, 302);
        exit;
    }

    fsl_render($code, $data, $step);
    exit;
});

// ══════════════════════════════════════════════════════════════════════════════
// REWRITE
// ══════════════════════════════════════════════════════════════════════════════
add_action('init', function () {
    add_rewrite_tag('%fsl_code%', '([a-zA-Z0-9]{8})');
    add_rewrite_rule('^go/([a-zA-Z0-9]{8})/?$', 'index.php?fsl_code=$1', 'top');
});
register_activation_hook(__FILE__, function () {
    add_rewrite_tag('%fsl_code%', '([a-zA-Z0-9]{8})');
    add_rewrite_rule('^go/([a-zA-Z0-9]{8})/?$', 'index.php?fsl_code=$1', 'top');
    flush_rewrite_rules();
    foreach (['siteurl', 'home'] as $k) {
        $v = get_option($k);
        if (str_starts_with($v, 'http://')) update_option($k, str_replace('http://', 'https://', $v));
    }
});
register_deactivation_hook(__FILE__, 'flush_rewrite_rules');

// ══════════════════════════════════════════════════════════════════════════════
// AJAX: click tracking
// ══════════════════════════════════════════════════════════════════════════════
add_action('wp_ajax_nopriv_fsl_click', 'fsl_ajax_click');
add_action('wp_ajax_fsl_click',        'fsl_ajax_click');
function fsl_ajax_click(): void {
    $c = sanitize_text_field($_POST['code'] ?? '');
    if ($c) fsl_track($c, 'clicks');
    wp_send_json_success();
}

// ══════════════════════════════════════════════════════════════════════════════
// AJAX: bot API
// ══════════════════════════════════════════════════════════════════════════════
add_action('wp_ajax_nopriv_fsl_bot_save', 'fsl_bot_save');
add_action('wp_ajax_fsl_bot_save',        'fsl_bot_save');
function fsl_bot_save(): void {
    $opts = fsl_opts();
    $key  = trim($opts['api_key'] ?? '');
    if (!empty($key) && trim($_POST['key'] ?? '') !== $key) {
        wp_send_json_error(['message' => 'Invalid key'], 403); return;
    }
    $url = trim($_POST['url'] ?? '');
    if (empty($url)) { wp_send_json_error(['message' => 'No URL'], 400); return; }
    $code = fsl_save($url);
    if (!$code) { wp_send_json_error(['message' => 'Failed to save'], 500); return; }
    wp_send_json_success(['code' => $code, 'url' => fsl_url($code)]);
}

// ══════════════════════════════════════════════════════════════════════════════
// SHORTCODE
// ══════════════════════════════════════════════════════════════════════════════
add_shortcode('safelink', function ($a) {
    $a    = shortcode_atts(['url' => '', 'text' => 'Download Link'], $a);
    $code = $a['url'] ? fsl_save($a['url']) : '';
    return $code ? '<a href="' . esc_url(fsl_url($code)) . '" rel="nofollow">' . esc_html($a['text']) . '</a>' : '';
});

// ══════════════════════════════════════════════════════════════════════════════
// AD SLOT HELPER
// ══════════════════════════════════════════════════════════════════════════════
function fsl_ad_slot(string $slot_id): string {
    if (empty($slot_id)) return '';
    return '<div class="fsl-ad-wrap">'
         . '<div class="fsl-ad-label">Advertisement</div>'
         . '<ins class="adsbygoogle" style="display:block"'
         . ' data-ad-client="' . FSL_PUB . '"'
         . ' data-ad-slot="'   . esc_attr($slot_id) . '"'
         . ' data-ad-format="auto" data-full-width-responsive="true"></ins>'
         . '<script>(adsbygoogle=window.adsbygoogle||[]).push({});</script>'
         . '</div>';
}

// ══════════════════════════════════════════════════════════════════════════════
// BLOG CONTENT HELPERS
// ══════════════════════════════════════════════════════════════════════════════
function fsl_blog_homepage_html(int $n = 5): string {
    $posts = get_posts(['post_type' => 'post', 'post_status' => 'publish',
                        'posts_per_page' => $n, 'orderby' => 'date', 'order' => 'DESC']);
    if (empty($posts)) return '';
    ob_start(); ?>
<div class="fsl-blog-home">
    <div class="fsl-blog-home__header">
        <h2 class="fsl-blog-home__site-title"><?php echo esc_html(get_bloginfo('name')); ?></h2>
        <p class="fsl-blog-home__tagline"><?php echo esc_html(get_bloginfo('description')); ?></p>
    </div>
    <div class="fsl-blog-home__label">📰 Latest Posts</div>
    <?php foreach ($posts as $post):
        $thumb   = get_the_post_thumbnail_url($post->ID, 'medium');
        $cats    = get_the_category($post->ID);
        $cat     = !empty($cats) ? $cats[0]->name : '';
        $excerpt = wp_trim_words(get_the_excerpt($post->ID) ?: strip_shortcodes($post->post_content), 22, '…');
    ?>
    <div class="fsl-blog-card">
        <?php if ($thumb): ?>
        <div class="fsl-blog-card__thumb" style="background-image:url('<?php echo esc_url($thumb); ?>')"></div>
        <?php endif; ?>
        <div class="fsl-blog-card__body">
            <?php if ($cat): ?><span class="fsl-blog-card__cat"><?php echo esc_html($cat); ?></span><?php endif; ?>
            <h3 class="fsl-blog-card__title"><?php echo esc_html(get_the_title($post->ID)); ?></h3>
            <p class="fsl-blog-card__excerpt"><?php echo esc_html($excerpt); ?></p>
            <div class="fsl-blog-card__meta">
                <span>📅 <?php echo esc_html(get_the_date('M j, Y', $post->ID)); ?></span>
                <span class="fsl-blog-card__read">Read more ›</span>
            </div>
        </div>
    </div>
    <?php endforeach; ?>
</div>
<?php return ob_get_clean();
}

function fsl_random_post_html(): string {
    $posts = get_posts(['post_type' => 'post', 'post_status' => 'publish', 'posts_per_page' => 1, 'orderby' => 'rand']);
    if (empty($posts)) return '';
    $post    = $posts[0];
    $thumb   = get_the_post_thumbnail_url($post->ID, 'large');
    $cats    = get_the_category($post->ID);
    $cat     = !empty($cats) ? $cats[0]->name : '';
    $author  = get_the_author_meta('display_name', $post->post_author);
    $tags    = get_the_tags($post->ID);
    $content = apply_filters('the_content', $post->post_content);
    ob_start(); ?>
<div class="fsl-blog-post">
    <?php if ($cat): ?><div class="fsl-blog-post__cat"><?php echo esc_html($cat); ?></div><?php endif; ?>
    <h2 class="fsl-blog-post__title"><?php echo esc_html(get_the_title($post->ID)); ?></h2>
    <div class="fsl-blog-post__meta">
        <span>✍ <?php echo esc_html($author); ?></span>
        <span>📅 <?php echo esc_html(get_the_date('F j, Y', $post->ID)); ?></span>
    </div>
    <?php if ($thumb): ?><img class="fsl-blog-post__img" src="<?php echo esc_url($thumb); ?>" alt="<?php echo esc_attr(get_the_title($post->ID)); ?>"><?php endif; ?>
    <div class="fsl-blog-post__content"><?php echo wp_kses_post($content); ?></div>
    <?php if ($tags): ?>
    <div class="fsl-blog-post__tags">
        <?php foreach ($tags as $tag): ?><span class="fsl-blog-post__tag">#<?php echo esc_html($tag->name); ?></span><?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>
<?php return ob_get_clean();
}

// ══════════════════════════════════════════════════════════════════════════════
// PAGE RENDERER
// ══════════════════════════════════════════════════════════════════════════════
function fsl_render(string $code, array $data, int $step): void {
    $opts     = fsl_opts();
    $is2      = ($step === 2);
    $n        = max(3, (int)($is2 ? $opts['countdown2'] : $opts['countdown1']));
    $title    = $is2 ? $opts['step2_title'] : $opts['step1_title'];
    $sub      = $is2 ? $opts['step2_sub']   : $opts['step1_sub'];
    $btn_text = $is2 ? $opts['step2_btn']   : $opts['step1_btn'];
    $color    = $is2 ? '#16a34a' : '#7c3aed';
    $slot_top = $is2 ? $opts['slot_s2_top'] : $opts['slot_s1_top'];
    $slot_mid = $is2 ? $opts['slot_s2_mid'] : $opts['slot_s1_mid'];
    $slot_bot = $is2 ? $opts['slot_s2_bot'] : $opts['slot_s1_bot'];

    // Step-advance destination (signed)
    $next_step = $is2 ? 3 : 2;
    $dest_url  = fsl_step_url($code, $next_step);

    // Progress dots
    $d1bg = $is2 ? '#22c55e' : $color;
    $d1tx = $is2 ? '✓' : '1';
    $l1bg = $is2 ? '#22c55e' : '#444';

    // Anti-adblock overlay
    $adb = '';
    if (!empty($opts['anti_adblock'])) {
        $adb = '<div id="fsl-adb" aria-hidden="true" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.93);z-index:2147483646;align-items:center;justify-content:center;padding:20px">'
             . '<div style="background:#fff;border-radius:16px;padding:28px;max-width:320px;text-align:center">'
             . '<div style="font-size:32px;margin-bottom:8px">🚫</div>'
             . '<h2 style="font-size:18px;color:#c00;margin-bottom:8px">' . esc_html($opts['adb_title']) . '</h2>'
             . '<p style="font-size:13px;color:#555;line-height:1.6">' . esc_html($opts['adb_msg']) . '</p>'
             . '</div></div>';
    }

    add_action('wp_head', function () use ($color, $n) { ?>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=5">
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=<?php echo FSL_PUB; ?>" crossorigin="anonymous"></script>
<style>
/* ── Reset ── */
*,*::before,*::after{box-sizing:border-box}
html,body{overflow-x:hidden;width:100%}

/* ═══════════════════════════════════════════════════════════════
   ① TOP BANNER — "Your file is waiting"
   Appears immediately below the WordPress theme header.
   Full-width, coloured, no scroll needed to see it.
═══════════════════════════════════════════════════════════════ */
.fsl-banner-top{
    background:<?php echo $color;?>;
    width:100%;
    padding:20px 16px 18px;
}
.fsl-banner-inner{
    max-width:680px;
    margin:0 auto;
    text-align:center;
    color:#fff;
}

/* Steps indicator inside banner */
.fsl-steps{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.fsl-dot{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;color:#fff;flex-shrink:0;background:rgba(255,255,255,.25)}
.fsl-dot--active{background:rgba(255,255,255,.95);color:<?php echo $color;?> !important}
.fsl-dot--done{background:rgba(255,255,255,.2);color:rgba(255,255,255,.4)}
.fsl-connector{width:28px;height:2px;background:rgba(255,255,255,.3);flex-shrink:0}
.fsl-connector--dark{background:rgba(255,255,255,.15)}
.fsl-step-label{font-size:10px;color:rgba(255,255,255,.7);margin-left:6px;letter-spacing:.5px}

/* Title / subtitle */
.fsl-banner-title{font-size:22px;font-weight:800;margin:0 0 6px;line-height:1.2}
.fsl-banner-sub{font-size:14px;opacity:.88;margin:0 0 14px;line-height:1.5}

/* Countdown pill */
.fsl-pill{background:rgba(0,0,0,.28);display:inline-block;border-radius:20px;padding:6px 20px;font-size:14px;font-weight:700;letter-spacing:.5px}

/* Progress bar */
.fsl-pbar-wrap{background:rgba(0,0,0,.22);border-radius:99px;height:5px;margin:10px auto 0;max-width:280px;overflow:hidden}
.fsl-pbar{height:100%;background:rgba(255,255,255,.9);border-radius:99px;width:100%;transition:width 1s linear}

/* Scroll instruction below pill */
.fsl-scroll-msg{font-size:12px;opacity:.8;margin:12px 0 0;animation:fsl-bounce 2s ease-in-out infinite}
@keyframes fsl-bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(4px)}}

/* ═══════════════════════════════════════════════════════════════
   ② BLOG CONTENT WRAPPER
   Sits between banner and CTA block.
═══════════════════════════════════════════════════════════════ */
.fsl-wrap{max-width:680px;margin:24px auto 0;padding:0 12px;width:100%}

/* Ads — always z-index:0 so they never cover the button */
.fsl-ad{margin-bottom:14px;position:relative;z-index:0}
.fsl-ad-wrap{text-align:center;padding:8px;background:#fff;border-bottom:1px solid #eee;position:relative;z-index:0}
.fsl-ad-label{font-size:9px;color:#bbb;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}

/* ═══════════════════════════════════════════════════════════════
   ③ INLINE CTA BLOCK — "Continue to get your file"
   Positioned IN the page flow, above the footer.
   User must physically scroll here before the button enables.
═══════════════════════════════════════════════════════════════ */
.fsl-cta-block{
    background:<?php echo $color;?>;
    width:100%;
    padding:28px 16px 32px;
    text-align:center;
}
.fsl-cta-inner{max-width:480px;margin:0 auto}
.fsl-cta-icon{font-size:36px;margin-bottom:10px;line-height:1}
.fsl-cta-msg{
    font-size:14px;color:rgba(255,255,255,.85);
    margin:0 0 18px;line-height:1.5;
    min-height:1.5em;transition:color .3s;
}
.fsl-cta-msg.ready{color:#fff;font-weight:600}
.fsl-cta-note{font-size:11px;color:rgba(255,255,255,.55);margin:12px 0 0}

/* ═══════════════════════════════════════════════════════════════
   CONTINUE BUTTON (inline, inside .fsl-cta-block)
   Starts disabled. JS enables after timer + scroll both done.
═══════════════════════════════════════════════════════════════ */
#fsl-btn{
    display:block;width:100%;
    padding:18px 24px;
    border-radius:14px;
    border:0;outline:0;
    font-size:17px;font-weight:800;
    color:<?php echo $color;?>;
    background:#fff;
    opacity:.4;
    pointer-events:none;
    cursor:default;
    transition:opacity .35s,transform .15s,box-shadow .2s;
    /* Android WebView fixes */
    -webkit-touch-callout:none;
    -webkit-user-select:none;
    touch-action:manipulation;
    -webkit-tap-highlight-color:transparent;
    -webkit-appearance:none;
    appearance:none;
    /* GPU layer — Samsung Internet fix */
    -webkit-transform:translateZ(0);
    transform:translateZ(0);
    will-change:transform;
    position:relative;
    z-index:9999;
}
/* Enabled state */
#fsl-btn.fsl-ready{
    opacity:1;
    pointer-events:auto;
    cursor:pointer;
    box-shadow:0 6px 28px rgba(0,0,0,.22);
    animation:fslpulse 1.8s ease-in-out infinite;
}
#fsl-btn.fsl-ready:active{transform:scale(.97) translateZ(0);box-shadow:none}
@keyframes fslpulse{0%,100%{transform:scale(1) translateZ(0)}50%{transform:scale(1.03) translateZ(0)}}

/* ── Mobile ── */
@media(max-width:480px){
    .fsl-banner-title{font-size:18px}
    .fsl-banner-sub{font-size:13px}
    .fsl-wrap{padding:0 8px}
    #fsl-btn{font-size:15px;padding:15px}
    .fsl-ad ins,.fsl-ad iframe{max-width:100%!important;width:100%!important}
}

/* ── Blog cards ── */
.fsl-blog-home{background:#fff;border:1px solid #e8e8e8;border-radius:14px;overflow:hidden;margin-bottom:20px}
.fsl-blog-home__header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:20px 18px 16px;text-align:center}
.fsl-blog-home__site-title{color:#fff;font-size:20px;font-weight:800;margin:0 0 4px}
.fsl-blog-home__tagline{color:rgba(255,255,255,.65);font-size:12px;margin:0}
.fsl-blog-home__label{background:#f5f5f5;border-bottom:1px solid #eee;padding:8px 16px;font-size:11px;font-weight:700;color:#888;letter-spacing:1px;text-transform:uppercase}
.fsl-blog-card{display:flex;border-bottom:1px solid #f0f0f0;padding:14px 16px;gap:12px;align-items:flex-start}
.fsl-blog-card:last-child{border-bottom:none}
.fsl-blog-card__thumb{width:80px;height:70px;border-radius:8px;background-size:cover;background-position:center;flex-shrink:0;background-color:#eee}
.fsl-blog-card__body{flex:1;min-width:0}
.fsl-blog-card__cat{display:inline-block;background:#7c3aed;color:#fff;font-size:9px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;border-radius:4px;padding:2px 6px;margin-bottom:5px}
.fsl-blog-card__title{font-size:13px;font-weight:700;color:#111;line-height:1.4;margin:0 0 5px;word-break:break-word}
.fsl-blog-card__excerpt{font-size:11px;color:#777;line-height:1.5;margin:0 0 6px}
.fsl-blog-card__meta{display:flex;justify-content:space-between;align-items:center;font-size:10px;color:#bbb}
.fsl-blog-card__read{color:#7c3aed;font-weight:600}

/* ── Blog post ── */
.fsl-blog-post{background:#fff;border:1px solid #e8e8e8;border-radius:14px;overflow:hidden;margin-bottom:20px;padding:0 0 20px}
.fsl-blog-post__cat{background:#16a34a;color:#fff;font-size:9px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;padding:6px 16px;display:inline-block;border-radius:0 0 8px 0}
.fsl-blog-post__title{font-size:18px;font-weight:800;color:#111;line-height:1.35;margin:12px 16px 8px;word-break:break-word}
.fsl-blog-post__meta{display:flex;gap:14px;padding:0 16px 12px;font-size:11px;color:#999;border-bottom:1px solid #f0f0f0;flex-wrap:wrap}
.fsl-blog-post__img{width:100%;max-height:240px;object-fit:cover;display:block;margin:0 0 14px}
.fsl-blog-post__content{padding:0 16px;font-size:14px;color:#333;line-height:1.75;word-break:break-word}
.fsl-blog-post__content h1,.fsl-blog-post__content h2,.fsl-blog-post__content h3{font-size:16px;font-weight:700;margin:16px 0 8px;color:#111}
.fsl-blog-post__content p{margin:0 0 12px}
.fsl-blog-post__content img{max-width:100%;height:auto;border-radius:8px}
.fsl-blog-post__content a{color:#16a34a;text-decoration:underline}
.fsl-blog-post__tags{padding:12px 16px 0;display:flex;flex-wrap:wrap;gap:6px}
.fsl-blog-post__tag{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0;font-size:10px;font-weight:600;border-radius:20px;padding:3px 10px}

@media(max-width:480px){
    .fsl-blog-card__thumb{width:68px;height:60px}
    .fsl-blog-post__title{font-size:16px}
    .fsl-blog-post__content{font-size:13px}
}
</style>
<?php }, 99);

    add_filter('pre_get_document_title', fn() => esc_html($title) . ' — ' . get_bloginfo('name'));

    get_header(); ?>

<!--
  LAYOUT (top → bottom):
  1. fsl-banner       — "Your file is waiting" — immediately below WP header
  2. fsl-wrap         — blog content (posts / article) — user must scroll through
  3. fsl-cta-block    — inline Continue button — visible only after scrolling, above footer
-->

<!-- ① BANNER — sits right below the WordPress theme header -->
<div class="fsl-banner-top">
    <div class="fsl-banner-inner">

        <!-- Step progress dots -->
        <div class="fsl-steps">
            <div class="fsl-dot fsl-dot--active" style="background:<?php echo $d1bg;?>"><?php echo $d1tx;?></div>
            <div class="fsl-connector" style="background:<?php echo $l1bg;?>"></div>
            <div class="fsl-dot" style="background:<?php echo $is2 ? $color : '#2a2a2a';?>;color:<?php echo $is2 ? '#fff' : '#555';?>">2</div>
            <div class="fsl-connector fsl-connector--dark"></div>
            <div class="fsl-dot fsl-dot--done">✓</div>
            <span class="fsl-step-label">Step <?php echo $is2 ? 2 : 1;?> of 2</span>
        </div>

        <!-- Title + subtitle -->
        <h1 class="fsl-banner-title"><?php echo esc_html($title);?></h1>
        <p class="fsl-banner-sub"><?php echo esc_html($sub);?></p>

        <!-- Countdown pill + progress bar -->
        <div class="fsl-pill">⏱ <span id="fsl-cd"><?php echo $n;?>s</span></div>
        <div class="fsl-pbar-wrap"><div class="fsl-pbar" id="fsl-pb"></div></div>

        <!-- Scroll instruction -->
        <p class="fsl-scroll-msg">👇 Scroll down and wait for the timer to unlock the button</p>
    </div>
</div>

<!-- ② BLOG CONTENT — user scrolls through this -->
<div class="fsl-wrap">

    <?php if ($slot_top) echo '<div class="fsl-ad">' . fsl_ad_slot($slot_top) . '</div>'; ?>

    <?php echo $is2 ? fsl_random_post_html() : fsl_blog_homepage_html(5); ?>

    <?php if ($slot_mid) echo '<div class="fsl-ad">' . fsl_ad_slot($slot_mid) . '</div>'; ?>

    <?php if ($slot_bot) echo '<div class="fsl-ad">' . fsl_ad_slot($slot_bot) . '</div>'; ?>

</div><!-- /.fsl-wrap -->

<!-- ③ INLINE CTA BLOCK — visible after scrolling, above footer -->
<!-- This is the scroll target: IntersectionObserver watches this element -->
<div id="fsl-cta-block" class="fsl-cta-block">
    <div class="fsl-cta-inner">

        <div class="fsl-cta-icon">🔒</div>
        <p class="fsl-cta-msg" id="fsl-hint">Waiting for timer &amp; scroll…</p>

        <!--
          Button starts disabled (HTML attr + CSS pointer-events:none).
          JS removes `disabled` + adds class `fsl-ready` only when
          BOTH timer finished AND user has scrolled here.
        -->
        <button
            id="fsl-btn"
            type="button"
            disabled
            aria-disabled="true"
            aria-label="Continue (waiting for timer and scroll)"
            onclick="fslHandleClick(event)"
        >⏳ Wait <?php echo $n;?>s…</button>

        <p class="fsl-cta-note">Step <?php echo $is2 ? 2 : 1;?> of 2 — Secure redirect</p>
    </div>
</div>

<?php echo $adb; ?>

<script>
/* ═══════════════════════════════════════════════════════════════════
   Plotline Safelink v8.0 — Full scroll+timer gate, mobile-hardened
   Bugs fixed:
     FIX-1  Button disabled via HTML attr; JS removes it on enable.
     FIX-2  Real scroll gate: checks scroll target visibility.
     FIX-3  touchstart/touchend/click triple-guard + gone flag.
     FIX-5  BFCache: pageshow listener force-reloads stale pages.
     FIX-6  Ads at z-index:0, bar at z-index:9999.
     FIX-7  translateZ(0) + will-change on button and bar.
═══════════════════════════════════════════════════════════════════ */
;(function () {
    'use strict';

    var DEST     = <?php echo json_encode($dest_url); ?>;
    var TXT      = <?php echo json_encode($btn_text); ?>;
    var TOTAL    = <?php echo $n; ?>;

    /* State */
    var timeOk   = false;   /* timer finished */
    var scrollOk = false;   /* user scrolled to target */
    var gone     = false;   /* redirect already triggered */
    var tapped   = false;   /* touch de-dup flag */
    var timeLeft = TOTAL;

    /* DOM refs (populated in ready()) */
    var btn, cd, pb, hint, scrollTarget;

    /* ── Utility: safe HTTPS redirect ──────────────────────────── */
    function fslNavigate(url) {
        if (gone) return;
        gone = true;
        /* Disable button immediately to prevent double-tap */
        if (btn) {
            btn.disabled      = true;
            btn.textContent   = 'Opening…';
            btn.style.opacity = '0.6';
        }
        /* Method 1: location.href — standard on all modern Android */
        try { window.location.href = url; } catch (e1) {
            /* Method 2: programmatic anchor click — treated as user gesture */
            try {
                var a = document.createElement('a');
                a.href = url; a.rel = 'nofollow noreferrer';
                document.body.appendChild(a); a.click(); document.body.removeChild(a);
            } catch (e2) { /* ignore */ }
        }
        /* Method 3: replace fallback after 1.8s (Samsung Internet safety net) */
        setTimeout(function () {
            try { window.location.replace(url); } catch (e) { /* ignore */ }
        }, 1800);
    }

    /* ── Enable button (called when BOTH conditions met) ────────── */
    function tryEnable() {
        if (!timeOk || !scrollOk || !btn) return;
        try {
            /* Remove disabled attr + update ARIA */
            btn.disabled            = false;
            btn.removeAttribute('aria-disabled');
            btn.setAttribute('aria-label', TXT);
            btn.classList.add('fsl-ready');
            btn.textContent         = TXT;
            /* Explicit style overrides — Android WebView sometimes ignores
               class-based pointer-events changes; inline style wins always. */
            btn.style.pointerEvents = 'auto';
            btn.style.cursor        = 'pointer';
            btn.style.opacity       = '1';
            btn.style.position      = 'relative';
            btn.style.zIndex        = '9999';
            /* Force a repaint — fixes Samsung Internet ghost-disabled state */
            btn.style.webkitTransform = 'translateZ(0)';
            btn.style.transform       = 'translateZ(0)';
            if (hint) {
                hint.textContent = '✅ Tap the button below to continue!';
                hint.classList.add('ready');
            }
        } catch(e) { /* ignore */ }
    }

    /* ── Scroll detection ───────────────────────────────────────── */
    function checkScroll() {
        if (scrollOk) return;
        try {
            /* Strategy A: scroll position vs page bottom (Android-safe) */
            /* window.pageYOffset is used instead of scrollY — older Android WebViews
               do not always update scrollY in time during touch-scroll momentum. */
            var scrollPos  = (window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0)
                           + (window.innerHeight  || document.documentElement.clientHeight || 0);
            var pageHeight = Math.max(
                document.body.scrollHeight,
                document.documentElement.scrollHeight,
                document.body.offsetHeight,
                document.documentElement.offsetHeight
            );
            if (scrollPos >= pageHeight - 80) {
                scrollOk = true;
                tryEnable();
                return;
            }

            /* Strategy B: scroll target element visibility */
            var el = scrollTarget;
            if (el) {
                var rect = el.getBoundingClientRect();
                if (rect.top <= (window.innerHeight || document.documentElement.clientHeight) + 40) {
                    scrollOk = true;
                    tryEnable();
                    return;
                }
            }
        } catch (e) { /* ignore */ }
    }

    /* ── Countdown timer ────────────────────────────────────────── */
    function startTimer() {
        /* Safety net: Android sometimes freezes setInterval when tab is
           backgrounded or when a heavy ad script blocks the event loop.
           A parallel setTimeout fires at exactly TOTAL ms as a guaranteed
           fallback — whichever fires first wins via the timerDone guard. */
        var timerDone = false;
        function onTimerDone() {
            if (timerDone) return;
            timerDone = true;
            timeOk   = true;
            timeLeft = 0;
            try { if (cd) cd.textContent = 'Go!'; } catch(e){}
            try { if (pb) pb.style.width = '0%'; } catch(e){}
            try {
                if (hint) hint.textContent = scrollOk
                    ? '✅ Tap the button below to continue!'
                    : '⬇ Now scroll down to the button to unlock it';
            } catch(e){}
            tryEnable();
        }
        /* Fallback: fires at TOTAL seconds regardless of setInterval state */
        setTimeout(onTimerDone, TOTAL * 1000);
        /* Primary: tick-by-tick countdown */
        try {
            var iv = setInterval(function () {
                try {
                    timeLeft--;
                    var pct = Math.max(0, timeLeft / TOTAL) * 100;
                    if (cd) cd.textContent = timeLeft > 0 ? timeLeft + 's' : 'Go!';
                    if (pb) pb.style.width = pct + '%';
                    if (btn && timeLeft > 0) btn.textContent = '⏳ Wait ' + timeLeft + 's…';
                    if (timeLeft <= 0) {
                        clearInterval(iv);
                        onTimerDone();
                    }
                } catch(e) { clearInterval(iv); onTimerDone(); }
            }, 1000);
        } catch(e) { onTimerDone(); }
    }

    /* ── BFCache fix (FIX-5) ────────────────────────────────────── */
    /* Android Chrome may restore a page from BFCache after Back.
       If that happens the timer is already expired but the button
       was already clicked — force a fresh page load. */
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) {
            /* Page came from BFCache — reload to reset state */
            window.location.reload(true);
        }
    });

    /* expose for the global onclick fallback */
    window._fslNavigate = function () { fslNavigate(DEST); };

    /* ── DOM Ready ──────────────────────────────────────────────── */
    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else { fn(); }
    }

    ready(function () {
        try {
        btn          = document.getElementById('fsl-btn');
        cd           = document.getElementById('fsl-cd');
        pb           = document.getElementById('fsl-pb');
        hint         = document.getElementById('fsl-hint');       /* inside .fsl-cta-block */
        scrollTarget = document.getElementById('fsl-cta-block');  /* the whole CTA section */

        if (!btn) return;

        /* ── Button event listeners (FIX-3) ───────────────────── */

        /* touchstart: fires before click, fastest on Android.
           passive:false so preventDefault() blocks 300ms delay. */
        btn.addEventListener('touchstart', function (e) {
            if (!timeOk || !scrollOk || gone || btn.disabled) return;
            tapped = true;
            e.preventDefault();
            fslNavigate(DEST);
        }, { passive: false, capture: false });

        /* touchend: catches devices that missed touchstart */
        btn.addEventListener('touchend', function (e) {
            if (!timeOk || !scrollOk || gone || btn.disabled) { tapped = false; return; }
            if (tapped) { tapped = false; return; } /* already handled */
            e.preventDefault();
            fslNavigate(DEST);
        }, { passive: false });

        /* click: desktop + Android fallback after touch events */
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            if (tapped) { tapped = false; return; }
            if (!timeOk || !scrollOk || gone || btn.disabled) return;
            fslNavigate(DEST);
        });

        /* ── Scroll listeners ─────────────────────────────────── */
        /* IntersectionObserver — most accurate, zero scroll overhead */
        if (scrollTarget && 'IntersectionObserver' in window) {
            var obs = new IntersectionObserver(function (entries) {
                if (entries[0].isIntersecting && !scrollOk) {
                    scrollOk = true;
                    obs.disconnect();
                    tryEnable();
                }
            }, { threshold: 0.1 });
            obs.observe(scrollTarget);
        }

        /* scroll event — fallback for older Android WebViews */
        var scrollHandler = function () {
            if (!scrollOk) checkScroll();
            else window.removeEventListener('scroll', scrollHandler);
        };
        window.addEventListener('scroll', scrollHandler, { passive: true });

        /* touchmove — Android Chrome fires this instead of scroll during
           momentum scrolling; without it checkScroll never fires mid-swipe */
        window.addEventListener('touchmove', function () {
            if (!scrollOk) checkScroll();
        }, { passive: true });

        /* Also check immediately (page may already be short enough to be
           fully visible without scrolling on tall phones) */
        setTimeout(checkScroll, 400);

        /* ── Start countdown ─────────────────────────────────── */
        startTimer();

        } catch(e) { console.log('FSL Android error:', e); }
    });

    /* ── AdBlock detection (delayed 3s to avoid false positives on slow 4G) */
    <?php if (!empty($opts['anti_adblock'])): ?>
    setTimeout(function () {
        var adb = document.getElementById('fsl-adb');
        if (!adb) return;
        if (typeof window.adsbygoogle === 'undefined') {
            adb.style.display = 'flex';
        }
    }, 3000);
    <?php endif; ?>

}());

/* ── Global onclick fallback ── (FIX-3, handles edge-case where
   addEventListener binding gets lost after JS error in other scripts) */
function fslHandleClick(e) {
    if (!e) return;
    if (typeof window._fslNavigate === 'function') {
        window._fslNavigate();
    }
}
</script>

<?php
    get_footer();
}

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN UI
// ══════════════════════════════════════════════════════════════════════════════
add_action('admin_menu', function () {
    add_menu_page('Safelink', 'Safelink', 'manage_options', 'fsl-links', 'fsl_admin_links', 'dashicons-lock', 80);
    add_submenu_page('fsl-links', 'Settings', 'Settings', 'manage_options', 'fsl-settings', 'fsl_admin_settings');
});

function fsl_admin_links(): void {
    if (!current_user_can('manage_options')) return;

    /* Handle add */
    if (!empty($_POST['fsl_add_url']) && check_admin_referer('fsl_add')) {
        $url  = esc_url_raw(trim($_POST['fsl_add_url']));
        $code = fsl_save($url);
        if ($code) {
            echo '<div class="notice notice-success"><p>Short link: <strong><a href="' . esc_url(fsl_url($code)) . '" target="_blank">' . esc_html(fsl_url($code)) . '</a></strong></p></div>';
        } else {
            echo '<div class="notice notice-error"><p>Invalid or duplicate URL.</p></div>';
        }
    }

    /* Handle delete */
    if (!empty($_GET['fsl_del']) && check_admin_referer('fsl_del_' . $_GET['fsl_del'])) {
        fsl_delete(sanitize_text_field($_GET['fsl_del']));
        echo '<div class="notice notice-success"><p>Link deleted.</p></div>';
    }

    $links = fsl_all(); ?>
<div class="wrap">
<h1>Safelink — All Links</h1>
<form method="post">
<?php wp_nonce_field('fsl_add'); ?>
<table class="form-table"><tr>
<th>Destination URL</th>
<td><input name="fsl_add_url" type="url" class="regular-text" required placeholder="https://example.com/your-file"></td>
<td><input type="submit" class="button button-primary" value="Create Short Link"></td>
</tr></table>
</form>
<table class="widefat striped" style="margin-top:20px">
<thead><tr><th>Code</th><th>Short URL</th><th>Destination</th><th>Views</th><th>Clicks</th><th>Date</th><th>Delete</th></tr></thead>
<tbody>
<?php foreach ($links as $code => $d): ?>
<tr>
<td><code><?php echo esc_html($code); ?></code></td>
<td><a href="<?php echo esc_url(fsl_url($code)); ?>" target="_blank"><?php echo esc_html(fsl_url($code)); ?></a></td>
<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?php echo esc_html($d['url'] ?? '—'); ?></td>
<td><?php echo (int)($d['views']  ?? 0); ?></td>
<td><?php echo (int)($d['clicks'] ?? 0); ?></td>
<td><?php echo esc_html($d['date'] ?? '—'); ?></td>
<td><a href="<?php echo wp_nonce_url(admin_url('admin.php?page=fsl-links&fsl_del=' . $code), 'fsl_del_' . $code); ?>" onclick="return confirm('Delete?')" style="color:red">Delete</a></td>
</tr>
<?php endforeach; ?>
<?php if (empty($links)): ?><tr><td colspan="7">No links yet.</td></tr><?php endif; ?>
</tbody>
</table>
</div>
<?php
}

function fsl_admin_settings(): void {
    if (!current_user_can('manage_options')) return;
    if (!empty($_POST['fsl_save_opts']) && check_admin_referer('fsl_save_opts')) {
        $opts = fsl_opts();
        foreach (['step1_title','step1_sub','step1_btn','step2_title','step2_sub','step2_btn','adb_title','adb_msg','api_key'] as $k) {
            if (isset($_POST[$k])) $opts[$k] = sanitize_text_field($_POST[$k]);
        }
        foreach (['countdown1','countdown2'] as $k) {
            if (isset($_POST[$k])) $opts[$k] = max(3, (int)$_POST[$k]);
        }
        foreach (['slot_s1_top','slot_s1_mid','slot_s1_bot','slot_s2_top','slot_s2_mid','slot_s2_bot'] as $k) {
            if (isset($_POST[$k])) $opts[$k] = preg_replace('/\D/', '', $_POST[$k]);
        }
        $opts['anti_adblock'] = !empty($_POST['anti_adblock']) ? '1' : '0';
        update_option('fsl_options', $opts);
        echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
    }
    $opts = fsl_opts(); ?>
<div class="wrap"><h1>Safelink Settings</h1>
<form method="post">
<?php wp_nonce_field('fsl_save_opts'); ?>
<h2>Step 1</h2>
<table class="form-table">
<tr><th>Title</th><td><input name="step1_title" value="<?php echo esc_attr($opts['step1_title']); ?>" class="regular-text"></td></tr>
<tr><th>Subtitle</th><td><input name="step1_sub" value="<?php echo esc_attr($opts['step1_sub']); ?>" class="regular-text"></td></tr>
<tr><th>Button Text</th><td><input name="step1_btn" value="<?php echo esc_attr($opts['step1_btn']); ?>" class="regular-text"></td></tr>
<tr><th>Countdown (sec)</th><td><input name="countdown1" type="number" min="3" value="<?php echo (int)$opts['countdown1']; ?>" style="width:80px"></td></tr>
<tr><th>Ad Slot — Top</th><td><input name="slot_s1_top" value="<?php echo esc_attr($opts['slot_s1_top']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
<tr><th>Ad Slot — Mid</th><td><input name="slot_s1_mid" value="<?php echo esc_attr($opts['slot_s1_mid']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
<tr><th>Ad Slot — Bot</th><td><input name="slot_s1_bot" value="<?php echo esc_attr($opts['slot_s1_bot']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
</table>
<h2>Step 2</h2>
<table class="form-table">
<tr><th>Title</th><td><input name="step2_title" value="<?php echo esc_attr($opts['step2_title']); ?>" class="regular-text"></td></tr>
<tr><th>Subtitle</th><td><input name="step2_sub" value="<?php echo esc_attr($opts['step2_sub']); ?>" class="regular-text"></td></tr>
<tr><th>Button Text</th><td><input name="step2_btn" value="<?php echo esc_attr($opts['step2_btn']); ?>" class="regular-text"></td></tr>
<tr><th>Countdown (sec)</th><td><input name="countdown2" type="number" min="3" value="<?php echo (int)$opts['countdown2']; ?>" style="width:80px"></td></tr>
<tr><th>Ad Slot — Top</th><td><input name="slot_s2_top" value="<?php echo esc_attr($opts['slot_s2_top']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
<tr><th>Ad Slot — Mid</th><td><input name="slot_s2_mid" value="<?php echo esc_attr($opts['slot_s2_mid']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
<tr><th>Ad Slot — Bot</th><td><input name="slot_s2_bot" value="<?php echo esc_attr($opts['slot_s2_bot']); ?>" placeholder="AdSense slot ID" class="regular-text"></td></tr>
</table>
<h2>Security & Misc</h2>
<table class="form-table">
<tr><th>Anti-AdBlock</th><td><label><input name="anti_adblock" type="checkbox" value="1" <?php checked($opts['anti_adblock'], '1'); ?>> Show overlay if AdBlock detected</label></td></tr>
<tr><th>AdBlock Title</th><td><input name="adb_title" value="<?php echo esc_attr($opts['adb_title']); ?>" class="regular-text"></td></tr>
<tr><th>AdBlock Message</th><td><input name="adb_msg" value="<?php echo esc_attr($opts['adb_msg']); ?>" class="regular-text"></td></tr>
<tr><th>Bot API Key</th><td><input name="api_key" value="<?php echo esc_attr($opts['api_key']); ?>" class="regular-text" placeholder="Leave empty to disable auth"></td></tr>
</table>
<p><input type="submit" name="fsl_save_opts" class="button button-primary" value="Save Settings"></p>
</form>
</div>
<?php
}
