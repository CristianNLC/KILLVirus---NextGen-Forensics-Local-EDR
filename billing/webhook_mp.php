<?php
// C:\wamp64\www\Proyecto_Antivirus\billing\webhook_mp.php

header('Content-Type: application/json');

function load_env_php($env_path) {
    if (file_exists($env_path)) {
        $lines = file($env_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '#') === 0) continue;
            if (strpos($line, '=') !== false) {
                list($key, $val) = explode('=', $line, 2);
                $key = trim($key);
                $val = trim(trim($val), '"\'');
                if (!getenv($key)) {
                    putenv("{$key}={$val}");
                    $_ENV[$key] = $val;
                }
            }
        }
    }
}

load_env_php(__DIR__ . '/../.env');

// 1. Claves de Configuración leídas desde variables de entorno / .env
$mp_access_token = getenv('MP_ACCESS_TOKEN') ?: ($_ENV['MP_ACCESS_TOKEN'] ?? '');
$supabase_url    = getenv('SUPABASE_URL')     ?: ($_ENV['SUPABASE_URL']     ?? '');
$supabase_key    = getenv('SUPABASE_KEY')     ?: ($_ENV['SUPABASE_KEY']     ?? '');

// 2. Capturar payload de Mercado Pago
$body = file_get_contents('php://input');
$event = json_decode($body, true);

if (!isset($event['type']) || $event['type'] !== 'payment') {
    http_response_code(200);
    exit(json_encode(["status" => "ignored", "reason" => "Not a payment event"]));
}

$payment_id = $event['data']['id'] ?? null;
if (!$payment_id) {
    http_response_code(400);
    exit(json_encode(["error" => "No payment ID"]));
}

// 3. Consultar a la API de Mercado Pago el estado real del pago
// Modo simulación local para testing
if ($payment_id === "999999999") {
    $payment_data = [
        "status" => "approved",
        "payer"  => ["email" => "comprador_mp@gmail.com"]
    ];
} else {
    // Consulta real a la API de Mercado Pago
    $ch = curl_init("https://api.mercadopago.com/v1/payments/{$payment_id}");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer {$mp_access_token}"
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $mp_response = curl_exec($ch);
    $http_code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200) {
        http_response_code(500);
        exit(json_encode(["error" => "Error al consultar Mercado Pago"]));
    }
    $payment_data = json_decode($mp_response, true);
}

// 4. Procesar solo pagos APROBADOS
if (isset($payment_data['status']) && $payment_data['status'] === 'approved') {
    $payer_email = $payment_data['payer']['email'] ?? 'cliente@killvirus.com';
    
    // Generar formato de clave KV-PRO-XXXX-XXXX-XXXX
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    $p1 = substr(str_shuffle($chars), 0, 4);
    $p2 = substr(str_shuffle($chars), 0, 4);
    $p3 = substr(str_shuffle($chars), 0, 4);
    $license_key = "KV-PRO-{$p1}-{$p2}-{$p3}";

    // Fecha de expiración (1 año por defecto)
    $expires_at = (new DateTime('+1 year', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z');

    // 5. Insertar directamente en Supabase
    $supabase_payload = [
        "clave_licencia"   => $license_key,
        "email_cliente"    => strtolower(trim($payer_email)),
        "plan"             => "anual",
        "estado"           => "activa",
        "max_dispositivos" => 1,
        "hardware_id"      => null,
        "fecha_expiracion" => $expires_at,
        "id_pago_pasarela" => (string)$payment_id,
        "notas"            => "Emitida por Webhook Mercado Pago"
    ];

    $ch_sb = curl_init("{$supabase_url}/rest/v1/licencias");
    curl_setopt($ch_sb, CURLOPT_POST, true);
    curl_setopt($ch_sb, CURLOPT_POSTFIELDS, json_encode($supabase_payload));
    curl_setopt($ch_sb, CURLOPT_HTTPHEADER, [
        "apikey: {$supabase_key}",
        "Authorization: Bearer {$supabase_key}",
        "Content-Type: application/json",
        "Prefer: return=representation"
    ]);
    curl_setopt($ch_sb, CURLOPT_RETURNTRANSFER, true);
    $sb_res = curl_exec($ch_sb);
    $sb_code = curl_getinfo($ch_sb, CURLINFO_HTTP_CODE);
    curl_close($ch_sb);

    // 6. Aquí se dispara el envío de mail al comprador con $license_key
    // mail($payer_email, "Tu Licencia KILLVirus PRO", "Tu clave es: " . $license_key);

    http_response_code(200);
    echo json_encode(["status" => "success", "license" => $license_key]);
    exit;
}

http_response_code(200);
echo json_encode(["status" => "pending_or_failed"]);